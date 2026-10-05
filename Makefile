all: idce

idce: src/lexer.l src/parser.y src/main.cpp src/analysis.cpp ml/feature_extractor.cpp
	flex -o src/lex.yy.c src/lexer.l
	bison -d -v -o src/parser.tab.c src/parser.y
	g++ -std=c++17 -Isrc -o idce src/lex.yy.c src/parser.tab.c src/main.cpp src/analysis.cpp ml/feature_extractor.cpp -ll

clean:
	rm -f src/lex.yy.c src/parser.tab.c src/parser.tab.h src/parser.output idce

run: idce
	./idce < input.ssa

debug: idce
	gdb ./idce