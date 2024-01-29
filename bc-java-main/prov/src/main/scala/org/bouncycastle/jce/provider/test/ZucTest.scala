package org.bouncycastle.jce.provider.test

import java.security.{AlgorithmParameters, Security}
import javax.crypto.{Cipher, SecretKey}
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.util.test.SimpleTest

object Main extends App {
  ZucTest.main(Array.empty)
}

object ZucTest extends SimpleTest {

  private val KEY128_1 = "00000000000000000000000000000000"
  private val KEY128_2 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
  private val KEY256_1 =
    "00000000000000000000000000000000" +
      "00000000000000000000000000000000"
  private val KEY256_2 =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"

  private val IV128_1 = "00000000000000000000000000000000"
  private val IV128_2 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
  private val IV200_1 =
    "00000000000000000000000000000000000000000000000000"
  private val IV200_2 =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF3F3F3F3F3F3F3F3F"

  private val initializationChars = Array.fill[Char](1024 * 1024 * 165)('0')
  private val initialString = new String(initializationChars)

  private val ZUC128_TEST1 = new TestCase(KEY128_1, IV128_1, "", initialString)
  private val ZUC128_TEST2 = new TestCase(KEY128_2, IV128_2, "", initialString)
  private val ZUC256_TEST1 = new TestCase(KEY256_1, IV200_1, "", initialString)
  private val ZUC256_TEST2 = new TestCase(KEY256_2, IV200_2, "", initialString)

  override def getName: String = "Zuc"

  private def testCipher(pCipher: Cipher, pTestCase: TestCase): Array[Byte] = {
    val myExpected = Hex.decode(pTestCase.theExpected)
    val myOutput = new Array[Byte](myExpected.length)
    val myData = Option(pTestCase.thePlainText).fold(new Array[Byte](myExpected.length))(Hex.decode)
    val myKey = new SecretKeySpec(Hex.decode(pTestCase.theKey), pCipher.getAlgorithm)
    val myIV = Hex.decode(pTestCase.theIV)

    pCipher.init(Cipher.ENCRYPT_MODE, myKey, new IvParameterSpec(myIV))
    pCipher.doFinal(myData, 0, myData.length, myOutput, 0)

    val algParams = AlgorithmParameters.getInstance(pCipher.getAlgorithm, "BC")
    algParams.init(new IvParameterSpec(myIV))

    pCipher.init(Cipher.DECRYPT_MODE, myKey, algParams)
    pCipher.doFinal(myData, 0, myData.length, myOutput, 0)

    myOutput
  }

  override def performTest(): Unit = {
    val zuc128 = Cipher.getInstance("Zuc-128", "BC")

    def measureTime(testCase: TestCase, cipher: Cipher): Unit = {
      val startTime = System.nanoTime()
      for (_ <- 0 to 9) {
        testCipher(cipher, testCase)
      }
      val endTime = System.nanoTime()
      val executionTime = endTime - startTime
      println(s"${cipher.getAlgorithm} Test1の処理時間: $executionTime ナノ秒")
    }

    measureTime(ZUC128_TEST1, zuc128)
    measureTime(ZUC128_TEST2, zuc128)

    val zuc256 = Cipher.getInstance("Zuc-256", "BC")
    measureTime(ZUC256_TEST1, zuc256)
    measureTime(ZUC256_TEST2, zuc256)
  }

  private class TestCase(val theKey: String, val theIV: String, val thePlainText: String, val theExpected: String)

  def main(args: Array[String]): Unit = {
    Security.addProvider(new BouncyCastleProvider())

    val test = ZucTest
    test.performTest()


    //println(result.toString)
    //Option(result.getException).getOrElse(new Throwable()).printStackTrace()
  }
}
