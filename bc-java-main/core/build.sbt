name := "core"

version := "1.0"

scalaVersion := "3.3.1" // 使用するScalaのバージョンに合わせて変更する

libraryDependencies ++= Seq(
  "org.bouncycastle" % "bcprov-jdk15on" % "1.68" // 最新バージョンに合わせて変更する
)

