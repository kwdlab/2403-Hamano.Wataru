# Overview
This project demonstrates the implementation and performance testing of the ZUC stream cipher in both Java and Scala. The program measures the time taken to encrypt and decrypt a 32-megabyte file using both ZUC-128 and ZUC-256 algorithms.

# Description
- The program here generates a 32 megabyte string at runtime, uses [bouncycastle](https://www.bouncycastle.org), encrypts and decrypts that string 1000 times using the ZUC-128 and ZUC-256 algorithms, and displays the time for each. 
- The ZucTest5.java file is prov/src/test/java/org/bouncycastle/jce/provider/test and is supposed to be executed by gradle.
- ZucTest.scala exists in core/src/main/scala/ZucTest.scala and is intended to be executed by sbt.
- When the program is executed, the time it takes to process each 32 megabyte string is displayed on the console.

# Requirement
- Java 11.0.20+8
- Scala 3.3.1

# Install
`git clone https://github.com/kwdlab/2403-Hamano.Wataru.git`

# Author
[Wataru Hamano](https://github.com/wataruh00001)

# License
[MIT](https://opensource.org/license/mit/)

# References
- [3rd Generation Partnership Project](https://www.3gpp.org/specifications-and-%20reports)
- [Java](https://www.java.com/ja/)
- [Scala](https://docs.scala-lang.org/ja/)
- [GitHub-bcgit/bc-java](https://github.com/bcgit/bc-java)
