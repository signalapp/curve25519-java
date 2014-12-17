
c:
	gcc -I headers/ ref10_extract/*.c

java:
	javac javasrc/*.java

test:
	java -cp . javasrc.Test
