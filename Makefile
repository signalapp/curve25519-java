
c:
	gcc -I headers/ ref10_extract/*.c

java:
	javac generated/*.java


test:
	java -cp . generated.Test
