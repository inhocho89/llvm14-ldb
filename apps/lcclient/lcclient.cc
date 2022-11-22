#include <arpa/inet.h>
#include <assert.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <map>
#include <memory>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include "waitgroup.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#define barrier()       asm volatile("" ::: "memory")

#define CYCLES_PER_US 2396

constexpr uint16_t kBarrierPort = 41;
constexpr uint64_t NORM = 100;

namespace {

using namespace std::chrono;
using sec = duration<double, std::micro>;

// <- ARGUMENTS FOR EXPERIMENT ->
// the number of worker threads to spawn.
int threads;
// the remote UDP address of the server.
unsigned long raddr, master;

std::ofstream json_out;
std::ofstream csv_out;

int total_agents = 1;
// Total duration of the experiment in us
//constexpr uint64_t kWarmUpTime = 2000000;
constexpr uint64_t kWarmUpTime = 0;
constexpr uint64_t kExperimentTime = 30000000;
// RTT
constexpr uint64_t kRTT = 1000;

std::vector<double> offered_loads;
double offered_load;

std::vector<uint64_t> frequencies;
uint64_t weight_sum;

/* client-side stat */
struct cstat_raw {
  double offered_rps;
  double rps;
  double goodput;
};

struct cstat {
  double offered_rps;
  double rps;
  double goodput;
};

struct payload {
  uint64_t term_index;
  uint64_t index;
  uint64_t hash;
};

struct work_unit {
  double start_us, duration_us;
  int hash;
  bool success;
  uint64_t term_index;
  uint64_t timing;
  uint64_t idx;
};

static inline __attribute__((always_inline)) uint64_t rdtsc(void) {
  uint32_t a, d;
  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return ((uint64_t)a) | (((uint64_t)d) << 32);
}

static inline __attribute__((always_inline)) void cpu_relax(void)
{
  asm volatile("pause");
}

static inline __attribute__((always_inline)) void __time_delay_us(uint64_t us)
{
  uint64_t cycles = us * CYCLES_PER_US;
  unsigned long start = rdtsc();

  while (rdtsc() - start < cycles)
    cpu_relax();
}

static uint64_t mc_swap64(uint64_t in) {
    /* Little endian, flip the bytes around until someone makes a faster/better
    * way to do this. */
    int64_t rv = 0;
    int i = 0;
     for(i = 0; i<8; i++) {
        rv = (rv << 8) | (in & 0xff);
        in >>= 8;
     }
    return rv;
}

uint64_t ntohll(uint64_t val) {
   return mc_swap64(val);
}

uint64_t htonll(uint64_t val) {
   return mc_swap64(val);
}

int TcpListen(uint16_t port, int backlog) {
  int fd;
  int opt = 1;
  struct sockaddr_in addr;

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "Failed to create socket\n");
    return -1;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
    fprintf(stderr, "Failed to set socket options\n");
    return -1;
  }

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "Failed to bind\n");
    return -1;
  }

  if (listen(fd, backlog) < 0) {
    fprintf(stderr, "Failed to listen\n");
    return -1;
  }

  return fd;
}

int TcpAccept(int fd, uint16_t port) {
  int s;
  struct sockaddr_in addr;
  int addrlen = sizeof(addr);

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  if ((s = accept(fd, (struct sockaddr *)&addr, (socklen_t*)&addrlen)) < 0) {
    fprintf(stderr, "Failed to accept\n");
    return -1;
  }

  return s;
}

int TcpDial(unsigned long ip, uint16_t port) {
  int fd;
  struct sockaddr_in addr;

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "Failed to create a socket\n");
    return -1;
  }
  bzero(&addr, sizeof(addr));

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = ip;
  addr.sin_port = htons(port);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
    fprintf(stderr, "Failed to connect: port = %u\n", port);
    return -1;
  }

  return fd;
}

ssize_t TcpReadFull(int fd, void *buf, size_t len) {
  char *pos = reinterpret_cast<char *>(buf);
  size_t n = 0;
  while (n < len) {
    ssize_t ret = read(fd, pos + n, len - n);
    if (ret < 0) return ret;
    n += ret;
  }
  assert(n == len);
  return n;
}

ssize_t TcpWriteFull(int fd, const void *buf, size_t len) {
  const char *pos = reinterpret_cast<const char *>(buf);
  size_t n = 0;
  while (n < len) {
    ssize_t ret = send(fd, buf, len, 0);
    if (ret < 0) return ret;
    assert(ret > 0);
    n += ret;
  }
  assert(n == len);
  return n;
}

class NetBarrier {
public:
  static constexpr uint64_t npara = 1;
  NetBarrier(int npeers) {
    threads /= total_agents;

    is_leader_ = true;
    int q = TcpListen(kBarrierPort, 4096);
    
    aggregator_ = TcpListen(kBarrierPort + 1, 4096);

    for (int i = 0; i < npeers; i++) {
      int c = TcpAccept(q, kBarrierPort);
      conns.push_back(c);
      TcpWriteFull(c, &threads, sizeof(threads));
      TcpWriteFull(c, &raddr, sizeof(raddr));
      TcpWriteFull(c, &total_agents, sizeof(total_agents));
      TcpWriteFull(c, &offered_load, sizeof(offered_load));

      for (size_t j = 0; j < npara; j++) {
        int c = TcpAccept(aggregator_, kBarrierPort + 1);
        agg_conns_.push_back(c);
      }
    }
  }

  NetBarrier(unsigned long leader) {
    int c = TcpDial(leader, kBarrierPort);
    conns.push_back(c);
    is_leader_ = false;
    TcpReadFull(c, &threads, sizeof(threads));
    TcpReadFull(c, &raddr, sizeof(raddr));
    TcpReadFull(c, &total_agents, sizeof(total_agents));
    TcpReadFull(c, &offered_load, sizeof(offered_load));

    for (size_t i = 0; i < npara; i++) {
      int c = TcpDial(master, kBarrierPort + 1);
      agg_conns_.push_back(c);
    }
  }

  bool Barrier() {
    char buf[1];
    if (is_leader_) {
      for (int c : conns) {
        if (TcpReadFull(c, buf, 1) != 1) return false;
      }
      for (int c : conns) {
        if (TcpWriteFull(c, buf, 1) != 1) return false;
      }
    } else {
      if (TcpWriteFull(conns[0], buf, 1) != 1) return false;
      if (TcpReadFull(conns[0], buf, 1) != 1) return false;
    }
    return true;
  }

  bool StartExperiment() { return Barrier(); }

  bool EndExperiment(std::vector<work_unit> &w, struct cstat_raw *csr) {
    if (is_leader_) {
      for (auto &c : conns) {
        struct cstat_raw rem_csr;
        TcpReadFull(c, &rem_csr, sizeof(rem_csr));
        csr->offered_rps += rem_csr.offered_rps;
        csr->rps += rem_csr.rps;
        csr->goodput += rem_csr.goodput;
      }
    } else {
      TcpWriteFull(conns[0], csr, sizeof(*csr));
    }
    GatherSamples(w);
    assert(Barrier());
    return is_leader_;
  }

  bool IsLeader() {
    return is_leader_;
  }

private:
  std::vector<int> conns;
  int aggregator_;
  std::vector<int> agg_conns_;
  bool is_leader_;

  void GatherSamples(std::vector<work_unit> &w) {
    std::vector<std::thread> th;
    if (is_leader_) {
      std::unique_ptr<std::vector<work_unit>> samples[agg_conns_.size()];
      for (size_t i = 0; i < agg_conns_.size(); ++i) {
        th.emplace_back(std::thread([&, i] {
          size_t nelem;
          TcpReadFull(agg_conns_[i], &nelem, sizeof(nelem));
          
          if (likely(nelem > 0)) {
            work_unit *wunits = new work_unit[nelem];
            TcpReadFull(agg_conns_[i], wunits, sizeof(work_unit) * nelem);
            std::vector<work_unit> v(wunits, wunits + nelem);
            delete[] wunits;

            samples[i].reset(new std::vector<work_unit>(std::move(v)));
          } else {
            samples[i].reset(new std::vector<work_unit>());
          }
        }));
      }

      for (auto &t : th) t.join();
      for (size_t i = 0; i < agg_conns_.size(); ++i) {
        auto &v = *samples[i];
        w.insert(w.end(), v.begin(), v.end());
      }
    } else {
      for (size_t i = 0; i < agg_conns_.size(); ++i) {
        th.emplace_back(std::thread([&, i] {
          size_t elems = w.size() / npara;
          work_unit *start = w.data() + elems * i;
          if (i == npara - 1)
            elems += w.size() % npara;
          TcpWriteFull(agg_conns_[i], &elems, sizeof(elems));
          if (likely(elems > 0))
            TcpWriteFull(agg_conns_[i], start, sizeof(work_unit) * elems);
        }));
      }
      for (auto &t : th) t.join();
    }
  }
};

static NetBarrier *b;

constexpr uint64_t kLucenePort = 8001;

// The maximum lateness to tolerate before dropping egress samples.
constexpr uint64_t kMaxCatchUpUS = 5;

uint64_t ChooseTerm() {
  uint64_t rand_ = (uint64_t)rand() % weight_sum;
  int i;

  for(i = 0; i < frequencies.size(); ++i) {
    if (rand_ < frequencies[i]) {
      break;
    } else {
      rand_ -= frequencies[i];
    }    
  }

  return i;
}

template <class Arrival>
std::vector<work_unit> GenerateWork(Arrival a, double cur_us,
                                    double last_us) {
  std::vector<work_unit> w;

  printf("Generating Work...\t");

  while (true) {
    cur_us += a();
    if (cur_us > last_us) break;
    w.emplace_back(work_unit{cur_us, 0, rand(), false, ChooseTerm()});
  }

  printf("Done\n");

  return w;
}

std::vector<work_unit> ClientWorker(
    int c, int id, WaitGroup *starter, WaitGroup *starter2,
    std::function<std::vector<work_unit>()> wf) {
  srand(time(NULL) * (id+1));
  std::vector<work_unit> w(wf());

  // Start the receiver thread.
  auto th = std::thread([&] {
    payload rp;
    ssize_t ret;
    uint64_t now;
    uint32_t idx;
    
    while (true) {
      ret = TcpReadFull(c, &rp, sizeof(rp));
      if (ret < 0) break;

      barrier();
      now = rdtsc();
      barrier();

      idx = ntohll(rp.index);
      idx = (idx - id) / threads;

      w[idx].duration_us = 1.0 * (now - w[idx].timing) / CYCLES_PER_US;
      w[idx].success = true;
    }
  });

  // Synchronized start of load generation.
  starter->Done();
  starter2->Wait();

  barrier();
  uint64_t expstart = rdtsc();
  barrier();

  payload p;
  auto wsize = w.size();

  printf("Started sending requests\n");
  for (unsigned int i = 0; i < wsize; ++i) {
    barrier();
    uint64_t now = rdtsc();
    barrier();
    if (now - expstart < w[i].start_us * CYCLES_PER_US) {
      __time_delay_us(w[i].start_us - 1.0 * (now - expstart) / CYCLES_PER_US);
      //usleep(w[i].start_us - 1.0 * (now - expstart) / CYCLES_PER_US);
    }
    if ((now - expstart) > (w[i].start_us + kMaxCatchUpUS) * CYCLES_PER_US)
      continue;

    w[i].idx = i * threads + id;
    barrier();
    w[i].timing = rdtsc();
    barrier();

    p.term_index = htonll(w[i].term_index);
    p.index = htonll(w[i].idx);
    p.hash = htonll(w[i].hash);

    // Send an RPC request.
    ssize_t ret = TcpWriteFull(c, &p, sizeof(p));
  }
  printf("Finished sending requests\n");

  __time_delay_us(1000);
  //usleep(kRTT + 2);
  shutdown(c, SHUT_RDWR);
  close(c);
  th.join();
  printf("Listener thread joined\n");

  return w;
}

std::vector<work_unit> RunExperiment(
    int threads, struct cstat_raw *csr, double *elapsed,
    std::function<std::vector<work_unit>()> wf) {
  // Create one TCP connection per thread.
  std::vector<int> conns;
  for (int i = 0; i < threads; ++i) {
    int outc = TcpDial(raddr, kLucenePort);
    if (outc < 0) {
      fprintf(stderr, "Cannot connect to server\n");
    }
    conns.push_back(outc);
  }

  // Launch a worker thread for each connection.
  WaitGroup starter;
  WaitGroup starter2;

  starter.Add(threads);
  starter2.Add(1);

  std::vector<std::thread> th;
  std::unique_ptr<std::vector<work_unit>> samples[threads];
  for (int i = 0; i < threads; ++i) {
    th.emplace_back(std::thread([&, i] {
      auto v = ClientWorker(conns[i], i, &starter, &starter2, wf);
      samples[i].reset(new std::vector<work_unit>(std::move(v)));
    }));
  }

  // Give the workers time to initialize, then start recording.
  starter.Wait();
  if (b && !b->StartExperiment()) {
    exit(0);
  }
  starter2.Done();

  // |--- start experiment duration timing ---|
  barrier();
  uint64_t start = rdtsc();
  barrier();

  // Wait for the workers to finish.
  for (auto &t : th) t.join();

  // |--- end experiment duration timing ---|
  barrier();
  uint64_t finish = rdtsc();
  barrier();

  // Force the connections to close.
  for (int c : conns) close(c);

  double elapsed_ = 1.0 * (finish - start) / CYCLES_PER_US;
  elapsed_ -= kWarmUpTime;

  // Aggregate all the samples together.
  std::vector<work_unit> w;
  uint64_t resps = 0;
  uint64_t offered = 0;
  uint64_t client_drop = 0;

  for (int i = 0; i < threads; ++i) {
    auto &v = *samples[i];
    double throughput;
    int resp_success;

    // Remove requests arrived during warm-up periods
    v.erase(std::remove_if(v.begin(), v.end(),
                        [](const work_unit &s) {
                          return ((s.start_us + s.duration_us) < kWarmUpTime);
                        }),
            v.end());

    offered += v.size();
    client_drop += std::count_if(v.begin(), v.end(), [](const work_unit &s) {
      return (s.duration_us == 0);
    });

    // Remove local drops
    v.erase(std::remove_if(v.begin(), v.end(),
                        [](const work_unit &s) {
                          return (s.duration_us == 0);
                        }),
            v.end());
    resp_success = std::count_if(v.begin(), v.end(), [](const work_unit &s) {
      return s.success;
    });
    throughput = static_cast<double>(resp_success) / elapsed_ * 1000000;

    resps += resp_success;

    w.insert(w.end(), v.begin(), v.end());
  }

  // Report results.
  if (csr) {
    csr->offered_rps = static_cast<double>(offered) / elapsed_ * 1000000;
    csr->rps = static_cast<double>(resps) / elapsed_ * 1000000;
  }

  *elapsed = elapsed_;

  return w;
}

void PrintHeader(std::ostream& os) {
  os << "num_threads,"
     << "offered_load,"
     << "throughput,"
     << "goodput,"
     << "cpu,"
     << "min,"
     << "mean,"
     << "p50,"
     << "p90,"
     << "p99,"
     << "p999,"
     << "p9999,"
     << "max,"
     << "reject_min"
     << "reject_mean"
     << "reject_p50"
     << "reject_p99"
     << "p1_credit,"
     << "mean_credit,"
     << "p99_credit,"
     << std::endl;
}

void PrintStatResults(std::vector<work_unit> w, struct cstat *cs) {
  if (w.size() == 0) {
    std::cout << std::setprecision(4) << std::fixed << threads * total_agents
    << "," << cs->offered_rps << "," << "-" << std::endl;
    return;
  }

  printf("Generating output...\n");

  w.erase(std::remove_if(w.begin(), w.end(),
			 [](const work_unit &s) {
			   return !s.success;
	}), w.end());

  double count = static_cast<double>(w.size());

  std::sort(w.begin(), w.end(),
      [](const work_unit &s1, const work_unit &s2) {
      return s1.duration_us > s2.duration_us;
  });

  std::ofstream latency_out;
  latency_out.open("latency.dist", std::fstream::out);

  for (work_unit &s : w) {
    latency_out << s.idx << "," << s.term_index << "," << s.duration_us << std::endl;
  }

  latency_out.close();

  std::ofstream cdf_out;
  cdf_out.open("latency.cdf", std::fstream::out);

  for (int i = 0; i <= 1000; ++i) {
    double i_ = i / 1000.0;
    cdf_out << i_ << "," << w[(count - 1) * (1.0 - i_)].duration_us << std::endl;
  }
  
  cdf_out.close();

  double sum = std::accumulate(
      w.begin(), w.end(), 0.0,
      [](double s, const work_unit &c) { return s + c.duration_us; });
  double mean = sum / w.size();
  double p50 = w[count * 0.5].duration_us;
  double p90 = w[count * 0.1].duration_us;
  double p99 = w[count * 0.01].duration_us;
  double p999 = w[count * 0.001].duration_us;
  double p9999 = w[count * 0.0001].duration_us;
  double min = w[w.size() - 1].duration_us;
  double max = w[0].duration_us;

  std::cout << std::setprecision(4) << std::fixed << threads * total_agents << ","
      << cs->offered_rps << "," << cs->rps << ","
      << min << "," << mean << "," << p50 << "," << p90 << "," << p99 << ","
      << p999 << "," << p9999 << "," << max << std::endl;
}

void SteadyStateExperiment(int threads, double offered_rps) {
  struct cstat_raw csr;
  struct cstat cs;
  double elapsed;

  memset(&csr, 0, sizeof(csr));
  std::vector<work_unit> w = RunExperiment(threads, &csr, &elapsed,
					   [=] {
    std::mt19937 rg(rand());
    std::exponential_distribution<double> rd(
        1.0 / (1000000.0 / (offered_rps / static_cast<double>(threads))));
    return GenerateWork(std::bind(rd, rg), 0, kExperimentTime);
  });

  if (b) {
    if (!b->EndExperiment(w, &csr))
      return;
  }

  cs = cstat{csr.offered_rps,
	     csr.rps,
	     csr.goodput};

  // Print the results.
  PrintStatResults(w, &cs);
}

void calculate_rates() {
  offered_loads.push_back(offered_load / (double)total_agents);
}

void ReadFreqTerms() {
  std::ifstream fin("frequent_terms.csv");

  std::string line, word;
  uint64_t freq;

  weight_sum = 0;

  while (std::getline(fin, line)) {
    std::stringstream ss(line);

    // word
    getline(ss, word, ',');
    getline(ss, word, ',');
    freq = (uint64_t)(std::stoi(word) / NORM);
    frequencies.push_back(freq);
    weight_sum += freq;
  }

  fin.close();
}

void AgentHandler(void *arg) {
  b = new NetBarrier(master);
  assert(b);

  calculate_rates();

  for (double i : offered_loads) {
    SteadyStateExperiment(threads, i);
  }
}

void ClientHandler(void *arg) {
  int pos;

  if (total_agents > 1) {
    b = new NetBarrier(total_agents - 1);
  }

  calculate_rates();

  for (double i : offered_loads) {
    SteadyStateExperiment(threads, i);
  }
}

}  // anonymous namespace

int main(int argc, char *argv[]) {
  int ret;

  if (argc < 2) {
    std::cerr << "usage: [cmd] ..." << std::endl;
    return -EINVAL;
  }

  ReadFreqTerms();

  std::string cmd = argv[1];
  if (cmd.compare("agent") == 0) {
    if (argc < 3) {
      std::cerr << "usage: agent [ip_address]"
	      << std::endl;
      return -EINVAL;
    }

    master = inet_addr(argv[2]);

    AgentHandler(NULL);
  } else if (cmd.compare("client") != 0) {
    std::cerr << "invalid command: " << cmd << std::endl;
    return -EINVAL;
  }

  if (argc < 6) {
    std::cerr << "usage: client [#threads] [remote_ip]"
	    << " [npeers] [offered_load]"
	    << std::endl;
    return -EINVAL;
  }

  threads = std::stoi(argv[2], nullptr, 0);

  raddr = inet_addr(argv[3]);
  if (ret) return -EINVAL;

  total_agents += std::stoi(argv[4], nullptr, 0);
  offered_load = std::stod(argv[5], nullptr);

  ClientHandler(NULL);

  return 0;
}
