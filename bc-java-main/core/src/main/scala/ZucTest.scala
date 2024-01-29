import java.security.{AlgorithmParameters, Security}
import javax.crypto.{Cipher, SecretKey}
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.jce.provider.BouncyCastleProvider
//import org.bouncycastle.util.test.{SimpleTest, Test, TestResult}

object ZucTest /*extends SimpleTest*/ {
  private val KEY128_1 =
    "00000000000000000000000000000000"
  private val KEY128_2 =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
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

  private val ZUC128_TEST1 = new TestCase(KEY128_1, IV128_1, initialString)
  private val ZUC128_TEST2 = new TestCase(KEY128_2, IV128_2, initialString)
  private val ZUC256_TEST1 = new TestCase(KEY256_1, IV200_1, initialString)
  private val ZUC256_TEST2 = new TestCase(KEY256_2, IV200_2, initialString)

  case class TestCase(theKey: String, theIV: String, thePlainText: String)

  private def testCipher(pCipher: Cipher, pTestCase: TestCase): Unit = {
    val myExpected = Hex.decode(pTestCase.thePlainText)
    val myOutput = new Array[Byte](myExpected.length)

    val myData =
      if (pTestCase.thePlainText != null) Hex.decode(pTestCase.thePlainText)
      else new Array[Byte](myExpected.length)

    val myKey = new SecretKeySpec(
      Hex.decode(pTestCase.theKey),
      pCipher.getAlgorithm
    )
    val myIV = Hex.decode(pTestCase.theIV)

    pCipher.init(Cipher.ENCRYPT_MODE, myKey, new IvParameterSpec(myIV))
    //Cipher.doFinal(myData, 0, myData.length, myOutput, 0)

    val algParams =
      AlgorithmParameters.getInstance(pCipher.getAlgorithm, "BC")
    algParams.init(new IvParameterSpec(myIV))

    pCipher.init(Cipher.DECRYPT_MODE, myKey, algParams)
    //pCipher.doFinal(myData, 0, myData.length, myOutput, 0)
  }

  def performTest(): Unit = {
    val zuc128 = Cipher.getInstance("Zuc-128", "BC")

    def measureTime(action: => Unit): Long = {
      val startTime = System.nanoTime()
      action
      val endTime = System.nanoTime()
      endTime - startTime
    }

    val executionTimeZuc128_0 = measureTime(testCipher(zuc128, ZUC128_TEST1))
    println(s"Zuc-128time: $executionTimeZuc128_0 nanomin")

    for (_ <- 0 to 999) {
      val executionTimeZuc128 = measureTime {
        testCipher(zuc128, ZUC128_TEST1)
      }
      print(s"${executionTimeZuc128 / 1000} ")
    }
    println("")
    println("")
    println("")
    for (_ <- 0 to 999) {
      val executionTimeZuc128_2 = measureTime {
        testCipher(zuc128, ZUC128_TEST2)
      }
      print(s"${executionTimeZuc128_2 / 1000} ")
    }
    println("")
    println("")
    println("")

    val zuc256 = Cipher.getInstance("Zuc-256", "BC")

    for (_ <- 0 to 999) {
      val executionTimeZuc256 = measureTime {
        testCipher(zuc256, ZUC256_TEST1)
      }
      print(s"${executionTimeZuc256 / 1000} ")
    }
    println("")
    println("")
    println("")

    for (_ <- 0 to 999) {
      val executionTimeZuc256_2 = measureTime {
        testCipher(zuc256, ZUC256_TEST2)
      }
      print(s"${executionTimeZuc256_2 / 1000} ")
    }
    println("")
  } 
  /*override def getName(): String = "ZucTest"*/

  def main(args: Array[String]): Unit = {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider)

    val test = ZucTest
    test.performTest()
  }
}
