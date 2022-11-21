ROOT_PATH=../../llvm14-ldb
CC = $(ROOT_PATH)/build/bin/clang
CXX = $(ROOT_PATH)/build/bin/clang++
AR = /usr/bin/ar
LIBLDB = $(ROOT_PATH)/libldb/libldb.a

analysis_src_ = ASCIIFoldingFilter.cpp Analyzer.cpp BaseCharFilter.cpp CachingTokenFilter.cpp \
								CharArraySet.cpp CharFilter.cpp CharReader.cpp CharStream.cpp CharTokenizer.cpp \
								ISOLatin1AccentFilter.cpp KeywordAnalyzer.cpp KeywordTokenizer.cpp \
								LengthFilter.cpp LetterTokenizer.cpp LowerCaseFilter.cpp LowerCaseTokenizer.cpp \
								MappingCharFilter.cpp NormalizeCharMap.cpp NumericTokenStream.cpp \
								PerFieldAnalyzerWrapper.cpp PorterStemFilter.cpp PorterStemmer.cpp \
								SimpleAnalyzer.cpp StopAnalyzer.cpp StopFilter.cpp TeeSinkTokenFilter.cpp \
								Token.cpp TokenFilter.cpp TokenStream.cpp Tokenizer.cpp WhitespaceAnalyzer.cpp \
								WhitespaceTokenizer.cpp WordlistLoader.cpp standard/StandardAnalyzer.cpp \
								standard/StandardFilter.cpp standard/StandardTokenizer.cpp \
								standard/StandardTokenizerImpl.cpp tokenattributes/FlagsAttribute.cpp \
								tokenattributes/OffsetAttribute.cpp tokenattributes/PayloadAttribute.cpp \
								tokenattributes/PositionIncrementAttribute.cpp \
								tokenattributes/TermAttribute.cpp tokenattributes/TypeAttribute.cpp

analysis_src = $(addprefix ../src/core/analysis/,$(analysis_src_))
analysis_obj = $(addprefix src/core/CMakeFiles/lucene++.dir/analysis/,$(addsuffix .o,$(analysis_src_)))

document_src_ = AbstractField.cpp CompressionTools.cpp DateField.cpp DateTools.cpp Document.cpp \
								Field.cpp FieldSelector.cpp LoadFirstFieldSelector.cpp NumberTools.cpp \
								NumericField.cpp SetBasedFieldSelector.cpp
document_src = $(addprefix ../src/core/document/,$(document_src_))
document_obj = $(addprefix src/core/CMakeFiles/lucene++.dir/document/,$(addsuffix .o,$(document_src_)))

index_src_ = AbstractAllTermDocs.cpp AllTermDocs.cpp BufferedDeletes.cpp ByteBlockPool.cpp \
						 ByteSliceReader.cpp ByteSliceWriter.cpp CharBlockPool.cpp CheckIndex.cpp \
						 CompoundFileReader.cpp CompoundFileWriter.cpp ConcurrentMergeScheduler.cpp \
						 DefaultSkipListReader.cpp DefaultSkipListWriter.cpp DirectoryReader.cpp \
						 DocConsumer.cpp DocConsumerPerThread.cpp DocFieldConsumer.cpp \
						 DocFieldConsumerPerField.cpp DocFieldConsumerPerThread.cpp DocFieldConsumers.cpp \
						 DocFieldConsumersPerField.cpp DocFieldConsumersPerThread.cpp DocFieldProcessor.cpp \
						 DocFieldProcessorPerField.cpp DocFieldProcessorPerThread.cpp DocInverter.cpp \
						 DocInverterPerField.cpp DocInverterPerThread.cpp DocumentsWriter.cpp \
						 DocumentsWriterThreadState.cpp FieldInfo.cpp FieldInfos.cpp FieldInvertState.cpp \
						 FieldSortedTermVectorMapper.cpp FieldsReader.cpp FieldsWriter.cpp \
						 FilterIndexReader.cpp FormatPostingsDocsConsumer.cpp FormatPostingsDocsWriter.cpp \
						 FormatPostingsFieldsConsumer.cpp FormatPostingsFieldsWriter.cpp \
						 FormatPostingsPositionsConsumer.cpp FormatPostingsPositionsWriter.cpp \
						 FormatPostingsTermsConsumer.cpp FormatPostingsTermsWriter.cpp \
						 FreqProxFieldMergeState.cpp FreqProxTermsWriter.cpp \
						 FreqProxTermsWriterPerField.cpp FreqProxTermsWriterPerThread.cpp IndexCommit.cpp \
						 IndexDeletionPolicy.cpp IndexFileDeleter.cpp IndexFileNameFilter.cpp \
						 IndexFileNames.cpp IndexReader.cpp IndexWriter.cpp IntBlockPool.cpp \
						 InvertedDocConsumer.cpp InvertedDocConsumerPerField.cpp \
						 InvertedDocConsumerPerThread.cpp InvertedDocEndConsumer.cpp \
						 InvertedDocEndConsumerPerField.cpp InvertedDocEndConsumerPerThread.cpp \
						 KeepOnlyLastCommitDeletionPolicy.cpp LogByteSizeMergePolicy.cpp \
						 LogDocMergePolicy.cpp LogMergePolicy.cpp MergeDocIDRemapper.cpp MergePolicy.cpp \
						 MergeScheduler.cpp MultiLevelSkipListReader.cpp MultiLevelSkipListWriter.cpp \
						 MultiReader.cpp MultipleTermPositions.cpp NormsWriter.cpp NormsWriterPerField.cpp \
						 NormsWriterPerThread.cpp ParallelReader.cpp Payload.cpp \
						 PositionBasedTermVectorMapper.cpp RawPostingList.cpp ReadOnlyDirectoryReader.cpp \
						 ReadOnlySegmentReader.cpp ReusableStringReader.cpp SegmentInfo.cpp \
						 SegmentInfoCollection.cpp SegmentInfos.cpp SegmentMergeInfo.cpp \
						 SegmentMergeQueue.cpp SegmentMerger.cpp SegmentReader.cpp SegmentTermDocs.cpp \
						 SegmentTermEnum.cpp SegmentTermPositionVector.cpp SegmentTermPositions.cpp \
						 SegmentTermVector.cpp SegmentWriteState.cpp SerialMergeScheduler.cpp \
						 SnapshotDeletionPolicy.cpp SortedTermVectorMapper.cpp StoredFieldsWriter.cpp \
						 StoredFieldsWriterPerThread.cpp Term.cpp TermBuffer.cpp TermDocs.cpp TermEnum.cpp \
						 TermFreqVector.cpp TermInfo.cpp TermInfosReader.cpp TermInfosWriter.cpp \
						 TermPositionVector.cpp TermPositions.cpp TermVectorEntry.cpp \
						 TermVectorEntryFreqSortedComparator.cpp TermVectorMapper.cpp \
						 TermVectorOffsetInfo.cpp TermVectorsReader.cpp TermVectorsTermsWriter.cpp \
						 TermVectorsTermsWriterPerField.cpp TermVectorsTermsWriterPerThread.cpp \
						 TermVectorsWriter.cpp TermsHash.cpp TermsHashConsumer.cpp \
						 TermsHashConsumerPerField.cpp TermsHashConsumerPerThread.cpp TermsHashPerField.cpp \
						 TermsHashPerThread.cpp
index_src = $(addprefix ../src/core/index/, $(index_src_))
index_obj = $(addprefix src/core/CMakeFiles/lucene++.dir/index/,$(addsuffix .o,$(index_src_)))

queryparser_src_ = FastCharStream.cpp MultiFieldQueryParser.cpp QueryParseError.cpp \
									 QueryParser.cpp QueryParserCharStream.cpp QueryParserConstants.cpp \
									 QueryParserToken.cpp QueryParserTokenManager.cpp
queryparser_src = $(addprefix ../src/core/queryparser/, $(queryparser_src_))
queryparser_obj = $(addprefix src/core/CMakeFiles/lucene++.dir/queryparser/,$(addsuffix .o,$(queryparser_src_)))

search_src_ = BooleanClause.cpp BooleanQuery.cpp BooleanScorer.cpp BooleanScorer2.cpp \
							CachingSpanFilter.cpp CachingWrapperFilter.cpp Collector.cpp \
							ComplexExplanation.cpp ConjunctionScorer.cpp ConstantScoreQuery.cpp \
							DefaultSimilarity.cpp DisjunctionMaxQuery.cpp DisjunctionMaxScorer.cpp \
							DisjunctionSumScorer.cpp DocIdSet.cpp DocIdSetIterator.cpp ExactPhraseScorer.cpp \
							Explanation.cpp FieldCache.cpp FieldCacheImpl.cpp FieldCacheRangeFilter.cpp \
							FieldCacheTermsFilter.cpp FieldComparator.cpp FieldComparatorSource.cpp \
							FieldDoc.cpp FieldDocSortedHitQueue.cpp FieldValueHitQueue.cpp Filter.cpp \
							FilterManager.cpp FilteredDocIdSet.cpp FilteredDocIdSetIterator.cpp \
							FilteredQuery.cpp FilteredTermEnum.cpp FuzzyQuery.cpp FuzzyTermEnum.cpp \
							HitQueue.cpp HitQueueBase.cpp IndexSearcher.cpp MatchAllDocsQuery.cpp \
							MultiPhraseQuery.cpp MultiSearcher.cpp MultiTermQuery.cpp \
						 	MultiTermQueryWrapperFilter.cpp NumericRangeFilter.cpp NumericRangeQuery.cpp \
							ParallelMultiSearcher.cpp PhrasePositions.cpp PhraseQuery.cpp PhraseQueue.cpp \
							PhraseScorer.cpp PositiveScoresOnlyCollector.cpp PrefixFilter.cpp PrefixQuery.cpp \
							PrefixTermEnum.cpp Query.cpp QueryTermVector.cpp QueryWrapperFilter.cpp \
							ReqExclScorer.cpp ReqOptSumScorer.cpp ScoreCachingWrappingScorer.cpp ScoreDoc.cpp \
							Scorer.cpp Searchable.cpp Searcher.cpp Similarity.cpp SimilarityDelegator.cpp \
							SingleTermEnum.cpp SloppyPhraseScorer.cpp Sort.cpp SortField.cpp SpanFilter.cpp \
							SpanFilterResult.cpp SpanQueryFilter.cpp TermQuery.cpp TermRangeFilter.cpp \
							TermRangeQuery.cpp TermRangeTermEnum.cpp TermScorer.cpp TimeLimitingCollector.cpp \
							TopDocs.cpp TopDocsCollector.cpp TopFieldCollector.cpp TopFieldDocs.cpp \
							TopScoreDocCollector.cpp Weight.cpp WildcardQuery.cpp WildcardTermEnum.cpp \
							function/ByteFieldSource.cpp function/CustomScoreProvider.cpp \
							function/CustomScoreQuery.cpp function/DocValues.cpp \
							function/DoubleFieldSource.cpp function/FieldCacheSource.cpp \
							function/FieldScoreQuery.cpp function/IntFieldSource.cpp \
							function/OrdFieldSource.cpp function/ReverseOrdFieldSource.cpp \
							function/ValueSource.cpp function/ValueSourceQuery.cpp \
							payloads/AveragePayloadFunction.cpp payloads/MaxPayloadFunction.cpp \
							payloads/MinPayloadFunction.cpp payloads/PayloadFunction.cpp \
							payloads/PayloadNearQuery.cpp payloads/PayloadSpanUtil.cpp \
							payloads/PayloadTermQuery.cpp spans/FieldMaskingSpanQuery.cpp \
							spans/NearSpansOrdered.cpp spans/NearSpansUnordered.cpp spans/SpanFirstQuery.cpp \
							spans/SpanNearQuery.cpp spans/SpanNotQuery.cpp spans/SpanOrQuery.cpp \
							spans/SpanQuery.cpp spans/SpanScorer.cpp spans/SpanTermQuery.cpp \
							spans/SpanWeight.cpp spans/Spans.cpp spans/TermSpans.cpp
search_src = $(addprefix ../src/core/search/, $(search_src_))
search_obj = $(addprefix src/core/CMakeFiles/lucene++.dir/search/,$(addsuffix .o,$(search_src_)))

store_src_ = BufferedIndexInput.cpp BufferedIndexOutput.cpp ChecksumIndexInput.cpp \
						 ChecksumIndexOutput.cpp Directory.cpp FSDirectory.cpp FSLockFactory.cpp \
						 FileSwitchDirectory.cpp IndexInput.cpp IndexOutput.cpp Lock.cpp LockFactory.cpp \
						 MMapDirectory.cpp NativeFSLockFactory.cpp NoLockFactory.cpp RAMDirectory.cpp \
						 RAMFile.cpp RAMInputStream.cpp RAMOutputStream.cpp SimpleFSDirectory.cpp \
						 SimpleFSLockFactory.cpp SingleInstanceLockFactory.cpp
store_src = $(addprefix ../src/core/store/, $(store_src_))
store_obj = $(addprefix src/core/CMakeFiles/lucene++.dir/store/,$(addsuffix .o,$(store_src_)))

util_src_ = Attribute.cpp AttributeSource.cpp Base64.cpp BitSet.cpp BitUtil.cpp BitVector.cpp \
						BufferedReader.cpp CharFolder.cpp Collator.cpp Constants.cpp CycleCheck.cpp \
						DocIdBitSet.cpp FieldCacheSanityChecker.cpp FileReader.cpp FileUtils.cpp \
						InfoStream.cpp InputStreamReader.cpp LuceneAllocator.cpp LuceneException.cpp \
						LuceneObject.cpp LuceneSignal.cpp LuceneSync.cpp LuceneThread.cpp MiscUtils.cpp \
						NumericUtils.cpp OpenBitSet.cpp OpenBitSetDISI.cpp OpenBitSetIterator.cpp \
						Random.cpp Reader.cpp ReaderUtil.cpp ScorerDocQueue.cpp SmallDouble.cpp \
						SortedVIntList.cpp StringReader.cpp StringUtils.cpp Synchronize.cpp TestPoint.cpp \
						ThreadPool.cpp UTF8Stream.cpp UnicodeUtils.cpp md5/md5.c unicode/guniprop.cpp
util_src = $(addprefix ../src/core/util/, $(util_src_))
util_obj = $(addprefix src/core/CMakeFiles/lucene++.dir/util/,$(addsuffix .o,$(util_src_)))

BOOST_FLAGS = -DBOOST_ALL_NO_LIB -DBOOST_ATOMIC_DYN_LINK -DBOOST_DATE_TIME_DYN_LINK \
							-DBOOST_FILESYSTEM_DYN_LINK -DBOOST_IOSTREAMS_DYN_LINK -DBOOST_REGEX_DYN_LINK \
							-DBOOST_SYSTEM_DYN_LINK -DBOOST_THREAD_DYN_LINK

CXX_FLAGS = $(BOOST_FLAGS) -Dlucene___EXPORTS -I./include -I../include/lucene++ \
						-I../src/core/include -O3 -DNDEBUG -fPIC -fvisibility=hidden \
						-fvisibility-inlines-hidden -DLPP_BUILDING_LIB -std=gnu++11 -Winvalid-pch -MD
CC_FLAGS = $(BOOST_FLAGS) -Dlucene___EXPORTS -I./include -I../include/lucene++ \
					 -I../src/core/include -O3 -DNDEBUG -fPIC -DLPP_BUILDING_LIB -MD

BOOST_LIBS = /usr/lib/x86_64-

LDB_CCFLAGS = -g -O3 -fdebug-default-version=3 -fno-omit-frame-pointer -I$(ROOT_PATH)/libldb/include

all: src/core/liblucene++.a

src/core/liblucene++.a: $(analysis_obj) $(document_obj) $(index_obj) $(queryparser_obj) \
	$(search_obj) $(store_obj) $(util_obj) $(LIBLDB)
	$(AR) qc $@ $(analysis_obj) \
		$(document_obj) $(index_obj) $(queryparser_obj) $(search_obj) $(store_obj) $(util_obj) \
		$(LIB_LDB) /usr/lib/x86_64-linux-gnu/libboost_date_time.so.1.74.0 \
	 	/usr/lib/x86_64-linux-gnu/libboost_filesystem.so.1.74.0 \
		/usr/lib/x86_64-linux-gnu/libboost_iostreams.so.1.74.0 \
		/usr/lib/x86_64-linux-gnu/libboost_regex.so.1.74.0 \
		/usr/lib/x86_64-linux-gnu/libboost_system.so.1.74.0 \
		/usr/lib/x86_64-linux-gnu/libboost_thread.so.1.74.0 \
		/usr/lib/x86_64-linux-gnu/libz.so /usr/lib/x86_64-linux-gnu/libboost_atomic.so.1.74.0

src/core/CMakeFiles/lucene++.dir/%.cpp.o: ../src/core/%.cpp
	$(CXX) $(LDB_CCFLAGS) $(CXX_FLAGS) -MT src/core/$@ -MF $@.d -o $@ -c $<

src/core/CMakeFiles/lucene++.dir/%.c.o: ../src/core/%.c
	$(CC) $(LDB_CCFLAGS) $(CC_FLAGS) -MT src/core/$@ -MF $@.d -o $@ -c $<

clean:
	rm -f $(analysis_obj) $(document_obj) $(index_obj) $(queryparser_obj) $(search_obj) \
	 	$(store_obj) $(util_obj) src/core/liblucene++.a
