convert:
	python ./convert.py

java:
	javac javasrc/*.java

test:
	java -cp . javasrc.Test
