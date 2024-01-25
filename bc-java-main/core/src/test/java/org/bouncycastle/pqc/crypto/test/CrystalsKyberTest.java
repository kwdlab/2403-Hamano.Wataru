package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.util.DEROtherInfo;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PQCOtherInfoGenerator;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

public class CrystalsKyberTest
    extends TestCase
{
    public void testPrivInfoGeneration()
        throws IOException
    {
        SecureRandom random = new SecureRandom();
        PQCOtherInfoGenerator.PartyU partyU = new PQCOtherInfoGenerator.PartyU(KyberParameters.kyber512, new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), Hex.decode("beef"), Hex.decode("cafe"), random);

        byte[] partA = partyU.getSuppPrivInfoPartA();

        PQCOtherInfoGenerator.PartyV partyV = new PQCOtherInfoGenerator.PartyV(KyberParameters.kyber512, new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), Hex.decode("beef"), Hex.decode("cafe"), random);

        byte[] partB = partyV.getSuppPrivInfoPartB(partA);

        DEROtherInfo otherInfoU = partyU.generate(partB);

        DEROtherInfo otherInfoV = partyV.generate();

        Assert.assertTrue(Arrays.areEqual(otherInfoU.getEncoded(), otherInfoV.getEncoded()));
    }
    
    public void testKyber()
    {
        /*
count = 0
seed = 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1
pk = D22302CBD3399FACC630991FC8F28BDB4354762541527678BCF61F65C241146C426D23B9BFAA6B7DF18C97F20C1B6125BF874B1D89475852C448215DB0EB7737F91480E8CEBD9A0871574F5AB62D9020175EC6927CA0B54C09818E42CF92A383172422C7DC1831D63B0C295DE75159DB8034E9E07F7B0B910C3C1E5FB66B3DC523F1FA6EB4910CB89A6C17562C83AB4C18D0CD7E0796592A372AA409B1C557347CCACDC4644A119064D06DD474929D1C6FB4D686E5491CE4BC89A30BB4B8C41BCE5157DFC1360823B1AB618C14B10F98C25067398EA7018C278A4B3DF31334D603B2044EF187CD9BC6CE42725BD962C264983E9E18155A8B9C47143D70460A26A56FE7658C1F150348C6087EF758AD167887860A007A5FC37358D43B5EBEE820ACEA474F0AC07B76802866199C61231D5C747C93774D2C1E0C1C67E6C81B82752173E125BAF39B4FD19A4F453DC57976B1D97FE6996992BBB65B7CB25D077BBAA6A13322899AF659CF1B3558C1B5001154B625809ED89AEEBB89E6EA7D67F723D045AB05715C42355DA6A5C8DD39C8ABE3037751A01ED1C7374919F3121B5A52C53D1487316769F80721DEEAAAD3C90F76E7AE9E12BA92B32B5FD457E3C752C2650DFB885771CB77AC3C785A8C562E6A1C63C2A55EA47CF8B90EB8225C123C346452566235B2F31823A33521E087937A345D8D663EEAA05658917BBAA008C2E335F8850A90A326D0E66432F44CEB8289E4ECB2D12958E984072ECACB88E1348FF0B55654ACBA5B54971CBAEBA88EC4B91A94C37192FA982BECB9F3DA421603B61A51BC8E36CBD053851C77B1B926B17A272AA9023246B02B3ED47F66A00BD5684823634E7CE58CF8F306E35B1E5322824D904801F0A2FA7C2BC9C252B0A56B7BA2AB0F636021745A70A9A43E2B0A8D615970B65309624B5184BCC30B911679AEDD76025FE3908FD67897B0CF4BE5A6F5413D7DD98564B23E42A93E4AA8821CD45054C643EDC1158DB6B3DEB13FB5A51EBD1A8A78B87225A7338E101104C4A220D9BDEDD48C85A1C2DAE781A80C40E13B87EAC73A764201C9B760CCFB1AE392699C7039D27C39362B27B8FC6F07A8A3D4410F1547C48A9997F62C61074452EF1515F8A649EBCA9437205A4E8A61606B41DAF6834D671F4D852C0C9C4096611648C6A3170678B1537CC1828D93580C9E5849A9653175ACB753F2BE7437BE45F6C603E485F2EC301BB42B6C37C225D7495A584AE231890AB5C8C35C268CF4BBB0213C096019319561A8A6947637AA40D006B415BB2CFA2237E0890B6A3BC134ABF8F6585E108D15940F91F4BF5B0C818055B21DEA6E63B553988C47F4B94E7CF800A493B4734705EDC56A4B6021C629500675876804CF0B951F038A5C7FE58E89774EF2992FD7C63099D352A7D21560B788B405709861817E59A96B3A3A83CBA803B16934331071905BBEC6532900155D8AC88CB32E4E21A3BD3A03FDEC325A51CD2773964E6784FCF1853737AA64EB67564727272661ABF84313A57A44B123C65509CFB7A6F6641CDCC3B57FE628C7B8192DB44FFBF5796A8613B1FA126F6076883C783DC24E2A4464C40B3A41CA70AE87620866CF4FCB2BD204BF5C283812BA056AC0C345E379C4BA24D750901279BB2F3A16F612BFADB35703332C7C136F68EAB6755C66B6A4AD1AABA7B768A58ACAACC10A459A1CC8EF29377BC200E4D315A30A6BCC3256F9734D06E9779CAA5442A9A16069081377C76E75154368072DC446ED6C8B8E622A21E383CF9BA1FB434E2ECC81E7B78CEE986B8FF798AB18CF9634543546284EDA2A26B47F05B735BCDB1202220076DC8B4E4B9F853533C8F6C7FF38817BA49712835785F17F14CA01D0C1C1E98810FE0B36E5B427157B9418449CEDD641A4293C85C32700102ACEC22EBAD98ED160A5F027BD4CDA57F1F3720A12C134654DD5E73F829676495390D0E7929D6034E9C55F7D55BA658BC587988E8AF94960F6CFB8D5AF7A0021535A6E25E437D49A780698BE22AC9953949F571B85A685725F8207A2B0AE849B601AB91B159B3DF4A154C2041E776070AFC42969322380917C97510799F3149131477E16663D3174C7C1CAEA788535C6C005A64F2868631B31B66E205FD38C1D84542D0F1B578F58C9BF5A0FAEAB6AB6494893053165EAFD465FC64A0C5F8F3F9003489415899D59A543D8208C54A3166529B53922
sk = 07638FB69868F3D320E5862BD96933FEB311B362093C9B5D50170BCED43F1B536D9A204BB1F22695950BA1F2A9E8EB828B284488760B3FC84FABA04275D5628E39C5B2471374283C503299C0AB49B66B8BBB56A4186624F919A2BA59BB08D8551880C2BEFC4F87F25F59AB587A79C327D792D54C974A69262FF8A78938289E9A87B688B083E0595FE218B6BB1505941CE2E81A5A64C5AAC60417256985349EE47A52420A5F97477B7236AC76BC70E8288729287EE3E34A3DBC3683C0B7B10029FC203418537E7466BA6385A8FF301EE12708F82AAA1E380FC7A88F8F205AB7E88D7E95952A55BA20D09B79A47141D62BF6EB7DD307B08ECA13A5BC5F6B68581C6865B27BBCDDAB142F4B2CBFF488C8A22705FAA98A2B9EEA3530C76662335CC7EA3A00777725EBCCCD2A4636B2D9122FF3AB77123CE0883C1911115E50C9E8A94194E48DD0D09CFFB3ADCD2C1E92430903D07ADBF00532031575AA7F9E7B5A1F3362DEC936D4043C05F2476C07578BC9CBAF2AB4E382727AD41686A96B2548820BB03B32F11B2811AD62F489E951632ABA0D1DF89680CC8A8B53B481D92A68D70B4EA1C3A6A561C0692882B5CA8CC942A8D495AFCB06DE89498FB935B775908FE7A03E324D54CC19D4E1AABD3593B38B19EE1388FE492B43127E5A504253786A0D69AD32601C28E2C88504A5BA599706023A61363E17C6B9BB59BDC697452CD059451983D738CA3FD034E3F5988854CA05031DB09611498988197C6B30D258DFE26265541C89A4B31D6864E9389B03CB74F7EC4323FB9421A4B9790A26D17B0398A26767350909F84D57B6694DF830664CA8B3C3C03ED2AE67B89006868A68527CCD666459AB7F056671000C6164D3A7F266A14D97CBD7004D6C92CACA770B844A4FA9B182E7B18CA885082AC5646FCB4A14E1685FEB0C9CE3372AB95365C04FD83084F80A23FF10A05BF15F7FA5ACC6C0CB462C33CA524FA6B8BB359043BA68609EAA2536E81D08463B19653B5435BA946C9ADDEB202B04B031CC960DCC12E4518D428B32B257A4FC7313D3A7980D80082E934F9D95C32B0A0191A23604384DD9E079BBBAA266D14C3F756B9F2133107433A4E83FA7187282A809203A4FAF841851833D121AC383843A5E55BC2381425E16C7DB4CC9AB5C1B0D91A47E2B8DE0E582C86B6B0D907BB360B97F40AB5D038F6B75C814B27D9B968D419832BC8C2BEE605EF6E5059D33100D90485D378450014221736C07407CAC260408AA64926619788B8601C2A752D1A6CBF820D7C7A04716203225B3895B9342D147A8185CFC1BB65BA06B4142339903C0AC4651385B45D98A8B19D28CD6BAB088787F7EE1B12461766B43CBCCB96434427D93C065550688F6948ED1B5475A425F1B85209D061C08B56C1CC069F6C0A7C6F29358CAB911087732A649D27C9B98F9A48879387D9B00C25959A71654D6F6A946164513E47A75D005986C2363C09F6B537ECA78B9303A5FA457608A586A653A347DB04DFCC19175B3A301172536062A658A95277570C8852CA8973F4AE123A334047DD711C8927A634A03388A527B034BF7A8170FA702C1F7C23EC32D18A2374890BE9C787A9409C82D192C4BB705A2F996CE405D85A4C1A1AB9B6AEB49CCE1C2F8A97C3516C72A00A46263BAA696BF25727719C3216423618FF33380934A6C10545C4C5C5155B12486181FC7A2319873978B6A2A67490F8256BD2196FE1792A4C00077B812EAE8BED3572499684AB3371876761E450C9F9D2768A36806D7AB2046C91F17599E9AC592990808DCD7B4D0919072F14EC361773B7252444C323C308326F4A30F8680D2F748F56A132B82674ED0184620B82AD2CB182C97B481626647491290A011CC73828685A8C367A5B9CF8D621B0D5C1EFF03172758BD004978C251CD51342228989CAE6332AC486437CB5C57D4307462865253BE217B3515C73DF405B7F28217AD0B8CF60C2FFFAA0A0048B1FB4ACDCDC38B5250CFEC356A6DE26CFA7A588FDC86F98C854AC64C7BFAA96F5A32CC0610934BAA6A586B9A2054F13BA274174AA0D2B3A81B96A940666F789B5A6BCDC0A6A0178A0C9A02578A493F6EEA0D2E6C13951C9F249A5E8DD71DD49A742D451F1ABBA19AF8C547855E0AFC728E90ABB499C9BEEB766F4729CDA22263E324D22302CBD3399FACC630991FC8F28BDB4354762541527678BCF61F65C241146C426D23B9BFAA6B7DF18C97F20C1B6125BF874B1D89475852C448215DB0EB7737F91480E8CEBD9A0871574F5AB62D9020175EC6927CA0B54C09818E42CF92A383172422C7DC1831D63B0C295DE75159DB8034E9E07F7B0B910C3C1E5FB66B3DC523F1FA6EB4910CB89A6C17562C83AB4C18D0CD7E0796592A372AA409B1C557347CCACDC4644A119064D06DD474929D1C6FB4D686E5491CE4BC89A30BB4B8C41BCE5157DFC1360823B1AB618C14B10F98C25067398EA7018C278A4B3DF31334D603B2044EF187CD9BC6CE42725BD962C264983E9E18155A8B9C47143D70460A26A56FE7658C1F150348C6087EF758AD167887860A007A5FC37358D43B5EBEE820ACEA474F0AC07B76802866199C61231D5C747C93774D2C1E0C1C67E6C81B82752173E125BAF39B4FD19A4F453DC57976B1D97FE6996992BBB65B7CB25D077BBAA6A13322899AF659CF1B3558C1B5001154B625809ED89AEEBB89E6EA7D67F723D045AB05715C42355DA6A5C8DD39C8ABE3037751A01ED1C7374919F3121B5A52C53D1487316769F80721DEEAAAD3C90F76E7AE9E12BA92B32B5FD457E3C752C2650DFB885771CB77AC3C785A8C562E6A1C63C2A55EA47CF8B90EB8225C123C346452566235B2F31823A33521E087937A345D8D663EEAA05658917BBAA008C2E335F8850A90A326D0E66432F44CEB8289E4ECB2D12958E984072ECACB88E1348FF0B55654ACBA5B54971CBAEBA88EC4B91A94C37192FA982BECB9F3DA421603B61A51BC8E36CBD053851C77B1B926B17A272AA9023246B02B3ED47F66A00BD5684823634E7CE58CF8F306E35B1E5322824D904801F0A2FA7C2BC9C252B0A56B7BA2AB0F636021745A70A9A43E2B0A8D615970B65309624B5184BCC30B911679AEDD76025FE3908FD67897B0CF4BE5A6F5413D7DD98564B23E42A93E4AA8821CD45054C643EDC1158DB6B3DEB13FB5A51EBD1A8A78B87225A7338E101104C4A220D9BDEDD48C85A1C2DAE781A80C40E13B87EAC73A764201C9B760CCFB1AE392699C7039D27C39362B27B8FC6F07A8A3D4410F1547C48A9997F62C61074452EF1515F8A649EBCA9437205A4E8A61606B41DAF6834D671F4D852C0C9C4096611648C6A3170678B1537CC1828D93580C9E5849A9653175ACB753F2BE7437BE45F6C603E485F2EC301BB42B6C37C225D7495A584AE231890AB5C8C35C268CF4BBB0213C096019319561A8A6947637AA40D006B415BB2CFA2237E0890B6A3BC134ABF8F6585E108D15940F91F4BF5B0C818055B21DEA6E63B553988C47F4B94E7CF800A493B4734705EDC56A4B6021C629500675876804CF0B951F038A5C7FE58E89774EF2992FD7C63099D352A7D21560B788B405709861817E59A96B3A3A83CBA803B16934331071905BBEC6532900155D8AC88CB32E4E21A3BD3A03FDEC325A51CD2773964E6784FCF1853737AA64EB67564727272661ABF84313A57A44B123C65509CFB7A6F6641CDCC3B57FE628C7B8192DB44FFBF5796A8613B1FA126F6076883C783DC24E2A4464C40B3A41CA70AE87620866CF4FCB2BD204BF5C283812BA056AC0C345E379C4BA24D750901279BB2F3A16F612BFADB35703332C7C136F68EAB6755C66B6A4AD1AABA7B768A58ACAACC10A459A1CC8EF29377BC200E4D315A30A6BCC3256F9734D06E9779CAA5442A9A16069081377C76E75154368072DC446ED6C8B8E622A21E383CF9BA1FB434E2ECC81E7B78CEE986B8FF798AB18CF9634543546284EDA2A26B47F05B735BCDB1202220076DC8B4E4B9F853533C8F6C7FF38817BA49712835785F17F14CA01D0C1C1E98810FE0B36E5B427157B9418449CEDD641A4293C85C32700102ACEC22EBAD98ED160A5F027BD4CDA57F1F3720A12C134654DD5E73F829676495390D0E7929D6034E9C55F7D55BA658BC587988E8AF94960F6CFB8D5AF7A0021535A6E25E437D49A780698BE22AC9953949F571B85A685725F8207A2B0AE849B601AB91B159B3DF4A154C2041E776070AFC42969322380917C97510799F3149131477E16663D3174C7C1CAEA788535C6C005A64F2868631B31B66E205FD38C1D84542D0F1B578F58C9BF5A0FAEAB6AB6494893053165EAFD465FC64A0C5F8F3F9003489415899D59A543D8208C54A3166529B539228A39E87D531F3527C207EDCC1DB7FADDCF9628391879B335C707839A0DB051A8B505D7CFAD1B497499323C8686325E4792F267AAFA3F87CA60D01CB54F29202A
ct = E97436B18AE42096AE6237C8E56E1B777A9C4CAF1B20D1C40F230B45DC38F1A68013EEE84F6F5633C39E7A5548092A23B46220934C698A6DBC88149D8EE666D427E697CBF464DB1A41BBC86F1C2EF998E46E51B5D94D560109E7319AD2316FD4C2EEACFBC01DC54D8A47E33C66A82094465D1FB1C6B7BD9331BA1CE5AF1C28ADBD130FEB1C35768D388D58444700643E70262889CBFED51AD328D0E3724E63B60253445A75A96B0FBF5B580DE3D2ACE22802DF3F1B009404575745F2F7A75CAE5E1E5AD414AD363CB5DFA48F7C6ED3587278EF58EE98B144438EAA66E5CD0BA800FB9799FBF63DE47D9904039AF5722E3D7E0A3C08A0A4B62F3743E179101EDBA93B081C79ED9A065BFFF65AD71D8548EAF76ADD4C32E3BC4D6C7551FB604CEB62CCF94C8A4EE41E7362B3E66ACB86C250E61BDC8AF162F1A2D9B29403D4976C37179C9A4927CDD6BF1ACACFE4A645EB5A59919FEFF17D86F5DCC77ABC52F56E70C41197E9B8328726C3D20C9D3ACE0CBFA0A7F50C5DDB2F1507D590071B6F1D17CA84DEA7A5930DC5B70F37AD7F447447481D4F14EA2718DB1CD8E096011DD617ED56BD0B2D0AE8C51BB0FF1B052CDC9D09BC6A772FD75877F762E72E6FC39F9A8E9EBF1E3ADEFA1ED897BF81BC6751DB4D637918BAD74C6A9D5D5E5F6E512A08C3D8165B0DE8DDEDEBC5066C2C44FC5A0C97531C0EEEEFED4C5565BEE4B33DD782C7178E91F8AE7AC30B3E010EEB25F7D558F7C953602EEE903C22C2D657EB32624B1B8F854232AD6F19C298830E6A8F6FEBCA91AEC693A08BA4294D0461F55A5AD25965BC81547036121E28A20DE2E658B358B9D17EB065B0A2D1D3BB029BCEC85FCE555728FAB7A77BAA183F92FD4430DD3F1E099F23BA59E1C737A9F56BBD0236AFA079CD7D37A15E407D47B745C891364D7DB99887C4C2816875A3FCC3B4B9FA646F7819871692434FED5588BC5AA53C7B33A12D163B584F11FB07535A84AE9DACDE81D8FC77B1368CAE470797069FC7C782FA96A7FEC30BC6F0ED7D4934C00B09A629029CC17E1BC433B2C7CF35E7895908848E417C184655C8E708F803C47B3C8BA45CFEBB9BCBB933C6CB72CCFC4C27863B8F9E0FE9A2FDB186359315BE6B46B50D19900D6E890B9FC4A87B517B24909B72A1ADE60ED549E2ED500CB60FDC7642F782AFC33133E1811613049F4229C00CC734969BF673E2690C3AB63DD0E064B9D2CAE9BD218A03808D7A4ED92D1F39ECDE7F102E8D47701AFCA94C788D7FF101BF8EB022BD25CD6CD12B2710FB0EEE09E467692E6D14BAAE47C771E4D2B10927CBDE8994B023210CAE0EFDA65306B4B30C6619DFB8A7937852D92759AAE5625AE717A1608B486AE3F25CB46B78F3D04B3410B41CE829CA6C29B7E6806740F8E818A72F3C082E24782BF63D4C3FC17C011D9AE0FA2DBA4EAD828158FB40C15E0C252924B77979F8068DAD4F8EE7A7DA07306293B25E507791906692C431F23592FAA77F4F6F9F5023413E0E812DE0681372D09B07CAE884DEDBB8AC2B80347D3511E4CFCA50CD752A16593858DF1A2E6A52887D5A2F81E70E57C65FA2753478A285C3896F6272133FA40A88DDB04D7985EF70C35D7413DBD32F49478694C509F2C97D21822F20740A86DD7ABDF66D0E632A254056DF5E0E7F013BCB7DFF01E38F881CFF77F1EDD48612A2677B7D1E4E62D5A6196340E26151EEA29D8EBD9786E38721B09EC974E336F2437505EAC34DE0270C0780C6B3A89520475481409864797DA4B6ACBE848225E25C7265A4E3BE16EE8CD8A225D2FDF4C498BA35332A553FE4066D73E758653F51A8A08913E469907DA5E7BF068E4C18486D1BE273BB4C674491BFE27F94453F64048086C93AE7F96FF7505B57CF3EDAC0AA5DE3A6B06470266DBC8945E952A2A73BD7CF8524E8EA00E1D0631DCA8F658145910F7248BE8266D0F98EF7152A112F3762F7B5356161E756D7EA4FCEFD3CBC44D4E59DCDA05ACC37F90B44C62431EB7610E15375984892B769D9417FCD6781B434F4C59191A020DADD81F0928E11C010617087015A968A5EA8B52DF8BB1706BF4AC7839FA80D52CC05C499091977B29B4AEABB7B1974D1B3BC097B23F3977CB0DF44E1A20318B4642D7A67D330F45A6FA5DEB96D8DDB9EAE323E61371BB6BEF4C13771D53BFA33B40408C813D3F539A29C4CF99C1D273E8561E2C53B505436CC3C
ss = C9786ED936508E178D55A1208C590A10F25CFBFEB50BE4207395A8B2F8AA192E
        */
        String temp = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
        String expectedPubKey = "D22302CBD3399FACC630991FC8F28BDB4354762541527678BCF61F65C241146C426D23B9BFAA6B7DF18C97F20C1B6125BF874B1D89475852C448215DB0EB7737F91480E8CEBD9A0871574F5AB62D9020175EC6927CA0B54C09818E42CF92A383172422C7DC1831D63B0C295DE75159DB8034E9E07F7B0B910C3C1E5FB66B3DC523F1FA6EB4910CB89A6C17562C83AB4C18D0CD7E0796592A372AA409B1C557347CCACDC4644A119064D06DD474929D1C6FB4D686E5491CE4BC89A30BB4B8C41BCE5157DFC1360823B1AB618C14B10F98C25067398EA7018C278A4B3DF31334D603B2044EF187CD9BC6CE42725BD962C264983E9E18155A8B9C47143D70460A26A56FE7658C1F150348C6087EF758AD167887860A007A5FC37358D43B5EBEE820ACEA474F0AC07B76802866199C61231D5C747C93774D2C1E0C1C67E6C81B82752173E125BAF39B4FD19A4F453DC57976B1D97FE6996992BBB65B7CB25D077BBAA6A13322899AF659CF1B3558C1B5001154B625809ED89AEEBB89E6EA7D67F723D045AB05715C42355DA6A5C8DD39C8ABE3037751A01ED1C7374919F3121B5A52C53D1487316769F80721DEEAAAD3C90F76E7AE9E12BA92B32B5FD457E3C752C2650DFB885771CB77AC3C785A8C562E6A1C63C2A55EA47CF8B90EB8225C123C346452566235B2F31823A33521E087937A345D8D663EEAA05658917BBAA008C2E335F8850A90A326D0E66432F44CEB8289E4ECB2D12958E984072ECACB88E1348FF0B55654ACBA5B54971CBAEBA88EC4B91A94C37192FA982BECB9F3DA421603B61A51BC8E36CBD053851C77B1B926B17A272AA9023246B02B3ED47F66A00BD5684823634E7CE58CF8F306E35B1E5322824D904801F0A2FA7C2BC9C252B0A56B7BA2AB0F636021745A70A9A43E2B0A8D615970B65309624B5184BCC30B911679AEDD76025FE3908FD67897B0CF4BE5A6F5413D7DD98564B23E42A93E4AA8821CD45054C643EDC1158DB6B3DEB13FB5A51EBD1A8A78B87225A7338E101104C4A220D9BDEDD48C85A1C2DAE781A80C40E13B87EAC73A764201C9B760CCFB1AE392699C7039D27C39362B27B8FC6F07A8A3D4410F1547C48A9997F62C61074452EF1515F8A649EBCA9437205A4E8A61606B41DAF6834D671F4D852C0C9C4096611648C6A3170678B1537CC1828D93580C9E5849A9653175ACB753F2BE7437BE45F6C603E485F2EC301BB42B6C37C225D7495A584AE231890AB5C8C35C268CF4BBB0213C096019319561A8A6947637AA40D006B415BB2CFA2237E0890B6A3BC134ABF8F6585E108D15940F91F4BF5B0C818055B21DEA6E63B553988C47F4B94E7CF800A493B4734705EDC56A4B6021C629500675876804CF0B951F038A5C7FE58E89774EF2992FD7C63099D352A7D21560B788B405709861817E59A96B3A3A83CBA803B16934331071905BBEC6532900155D8AC88CB32E4E21A3BD3A03FDEC325A51CD2773964E6784FCF1853737AA64EB67564727272661ABF84313A57A44B123C65509CFB7A6F6641CDCC3B57FE628C7B8192DB44FFBF5796A8613B1FA126F6076883C783DC24E2A4464C40B3A41CA70AE87620866CF4FCB2BD204BF5C283812BA056AC0C345E379C4BA24D750901279BB2F3A16F612BFADB35703332C7C136F68EAB6755C66B6A4AD1AABA7B768A58ACAACC10A459A1CC8EF29377BC200E4D315A30A6BCC3256F9734D06E9779CAA5442A9A16069081377C76E75154368072DC446ED6C8B8E622A21E383CF9BA1FB434E2ECC81E7B78CEE986B8FF798AB18CF9634543546284EDA2A26B47F05B735BCDB1202220076DC8B4E4B9F853533C8F6C7FF38817BA49712835785F17F14CA01D0C1C1E98810FE0B36E5B427157B9418449CEDD641A4293C85C32700102ACEC22EBAD98ED160A5F027BD4CDA57F1F3720A12C134654DD5E73F829676495390D0E7929D6034E9C55F7D55BA658BC587988E8AF94960F6CFB8D5AF7A0021535A6E25E437D49A780698BE22AC9953949F571B85A685725F8207A2B0AE849B601AB91B159B3DF4A154C2041E776070AFC42969322380917C97510799F3149131477E16663D3174C7C1CAEA788535C6C005A64F2868631B31B66E205FD38C1D84542D0F1B578F58C9BF5A0FAEAB6AB6494893053165EAFD465FC64A0C5F8F3F9003489415899D59A543D8208C54A3166529B53922";
        String expectedPrivKey = "07638FB69868F3D320E5862BD96933FEB311B362093C9B5D50170BCED43F1B536D9A204BB1F22695950BA1F2A9E8EB828B284488760B3FC84FABA04275D5628E39C5B2471374283C503299C0AB49B66B8BBB56A4186624F919A2BA59BB08D8551880C2BEFC4F87F25F59AB587A79C327D792D54C974A69262FF8A78938289E9A87B688B083E0595FE218B6BB1505941CE2E81A5A64C5AAC60417256985349EE47A52420A5F97477B7236AC76BC70E8288729287EE3E34A3DBC3683C0B7B10029FC203418537E7466BA6385A8FF301EE12708F82AAA1E380FC7A88F8F205AB7E88D7E95952A55BA20D09B79A47141D62BF6EB7DD307B08ECA13A5BC5F6B68581C6865B27BBCDDAB142F4B2CBFF488C8A22705FAA98A2B9EEA3530C76662335CC7EA3A00777725EBCCCD2A4636B2D9122FF3AB77123CE0883C1911115E50C9E8A94194E48DD0D09CFFB3ADCD2C1E92430903D07ADBF00532031575AA7F9E7B5A1F3362DEC936D4043C05F2476C07578BC9CBAF2AB4E382727AD41686A96B2548820BB03B32F11B2811AD62F489E951632ABA0D1DF89680CC8A8B53B481D92A68D70B4EA1C3A6A561C0692882B5CA8CC942A8D495AFCB06DE89498FB935B775908FE7A03E324D54CC19D4E1AABD3593B38B19EE1388FE492B43127E5A504253786A0D69AD32601C28E2C88504A5BA599706023A61363E17C6B9BB59BDC697452CD059451983D738CA3FD034E3F5988854CA05031DB09611498988197C6B30D258DFE26265541C89A4B31D6864E9389B03CB74F7EC4323FB9421A4B9790A26D17B0398A26767350909F84D57B6694DF830664CA8B3C3C03ED2AE67B89006868A68527CCD666459AB7F056671000C6164D3A7F266A14D97CBD7004D6C92CACA770B844A4FA9B182E7B18CA885082AC5646FCB4A14E1685FEB0C9CE3372AB95365C04FD83084F80A23FF10A05BF15F7FA5ACC6C0CB462C33CA524FA6B8BB359043BA68609EAA2536E81D08463B19653B5435BA946C9ADDEB202B04B031CC960DCC12E4518D428B32B257A4FC7313D3A7980D80082E934F9D95C32B0A0191A23604384DD9E079BBBAA266D14C3F756B9F2133107433A4E83FA7187282A809203A4FAF841851833D121AC383843A5E55BC2381425E16C7DB4CC9AB5C1B0D91A47E2B8DE0E582C86B6B0D907BB360B97F40AB5D038F6B75C814B27D9B968D419832BC8C2BEE605EF6E5059D33100D90485D378450014221736C07407CAC260408AA64926619788B8601C2A752D1A6CBF820D7C7A04716203225B3895B9342D147A8185CFC1BB65BA06B4142339903C0AC4651385B45D98A8B19D28CD6BAB088787F7EE1B12461766B43CBCCB96434427D93C065550688F6948ED1B5475A425F1B85209D061C08B56C1CC069F6C0A7C6F29358CAB911087732A649D27C9B98F9A48879387D9B00C25959A71654D6F6A946164513E47A75D005986C2363C09F6B537ECA78B9303A5FA457608A586A653A347DB04DFCC19175B3A301172536062A658A95277570C8852CA8973F4AE123A334047DD711C8927A634A03388A527B034BF7A8170FA702C1F7C23EC32D18A2374890BE9C787A9409C82D192C4BB705A2F996CE405D85A4C1A1AB9B6AEB49CCE1C2F8A97C3516C72A00A46263BAA696BF25727719C3216423618FF33380934A6C10545C4C5C5155B12486181FC7A2319873978B6A2A67490F8256BD2196FE1792A4C00077B812EAE8BED3572499684AB3371876761E450C9F9D2768A36806D7AB2046C91F17599E9AC592990808DCD7B4D0919072F14EC361773B7252444C323C308326F4A30F8680D2F748F56A132B82674ED0184620B82AD2CB182C97B481626647491290A011CC73828685A8C367A5B9CF8D621B0D5C1EFF03172758BD004978C251CD51342228989CAE6332AC486437CB5C57D4307462865253BE217B3515C73DF405B7F28217AD0B8CF60C2FFFAA0A0048B1FB4ACDCDC38B5250CFEC356A6DE26CFA7A588FDC86F98C854AC64C7BFAA96F5A32CC0610934BAA6A586B9A2054F13BA274174AA0D2B3A81B96A940666F789B5A6BCDC0A6A0178A0C9A02578A493F6EEA0D2E6C13951C9F249A5E8DD71DD49A742D451F1ABBA19AF8C547855E0AFC728E90ABB499C9BEEB766F4729CDA22263E324D22302CBD3399FACC630991FC8F28BDB4354762541527678BCF61F65C241146C426D23B9BFAA6B7DF18C97F20C1B6125BF874B1D89475852C448215DB0EB7737F91480E8CEBD9A0871574F5AB62D9020175EC6927CA0B54C09818E42CF92A383172422C7DC1831D63B0C295DE75159DB8034E9E07F7B0B910C3C1E5FB66B3DC523F1FA6EB4910CB89A6C17562C83AB4C18D0CD7E0796592A372AA409B1C557347CCACDC4644A119064D06DD474929D1C6FB4D686E5491CE4BC89A30BB4B8C41BCE5157DFC1360823B1AB618C14B10F98C25067398EA7018C278A4B3DF31334D603B2044EF187CD9BC6CE42725BD962C264983E9E18155A8B9C47143D70460A26A56FE7658C1F150348C6087EF758AD167887860A007A5FC37358D43B5EBEE820ACEA474F0AC07B76802866199C61231D5C747C93774D2C1E0C1C67E6C81B82752173E125BAF39B4FD19A4F453DC57976B1D97FE6996992BBB65B7CB25D077BBAA6A13322899AF659CF1B3558C1B5001154B625809ED89AEEBB89E6EA7D67F723D045AB05715C42355DA6A5C8DD39C8ABE3037751A01ED1C7374919F3121B5A52C53D1487316769F80721DEEAAAD3C90F76E7AE9E12BA92B32B5FD457E3C752C2650DFB885771CB77AC3C785A8C562E6A1C63C2A55EA47CF8B90EB8225C123C346452566235B2F31823A33521E087937A345D8D663EEAA05658917BBAA008C2E335F8850A90A326D0E66432F44CEB8289E4ECB2D12958E984072ECACB88E1348FF0B55654ACBA5B54971CBAEBA88EC4B91A94C37192FA982BECB9F3DA421603B61A51BC8E36CBD053851C77B1B926B17A272AA9023246B02B3ED47F66A00BD5684823634E7CE58CF8F306E35B1E5322824D904801F0A2FA7C2BC9C252B0A56B7BA2AB0F636021745A70A9A43E2B0A8D615970B65309624B5184BCC30B911679AEDD76025FE3908FD67897B0CF4BE5A6F5413D7DD98564B23E42A93E4AA8821CD45054C643EDC1158DB6B3DEB13FB5A51EBD1A8A78B87225A7338E101104C4A220D9BDEDD48C85A1C2DAE781A80C40E13B87EAC73A764201C9B760CCFB1AE392699C7039D27C39362B27B8FC6F07A8A3D4410F1547C48A9997F62C61074452EF1515F8A649EBCA9437205A4E8A61606B41DAF6834D671F4D852C0C9C4096611648C6A3170678B1537CC1828D93580C9E5849A9653175ACB753F2BE7437BE45F6C603E485F2EC301BB42B6C37C225D7495A584AE231890AB5C8C35C268CF4BBB0213C096019319561A8A6947637AA40D006B415BB2CFA2237E0890B6A3BC134ABF8F6585E108D15940F91F4BF5B0C818055B21DEA6E63B553988C47F4B94E7CF800A493B4734705EDC56A4B6021C629500675876804CF0B951F038A5C7FE58E89774EF2992FD7C63099D352A7D21560B788B405709861817E59A96B3A3A83CBA803B16934331071905BBEC6532900155D8AC88CB32E4E21A3BD3A03FDEC325A51CD2773964E6784FCF1853737AA64EB67564727272661ABF84313A57A44B123C65509CFB7A6F6641CDCC3B57FE628C7B8192DB44FFBF5796A8613B1FA126F6076883C783DC24E2A4464C40B3A41CA70AE87620866CF4FCB2BD204BF5C283812BA056AC0C345E379C4BA24D750901279BB2F3A16F612BFADB35703332C7C136F68EAB6755C66B6A4AD1AABA7B768A58ACAACC10A459A1CC8EF29377BC200E4D315A30A6BCC3256F9734D06E9779CAA5442A9A16069081377C76E75154368072DC446ED6C8B8E622A21E383CF9BA1FB434E2ECC81E7B78CEE986B8FF798AB18CF9634543546284EDA2A26B47F05B735BCDB1202220076DC8B4E4B9F853533C8F6C7FF38817BA49712835785F17F14CA01D0C1C1E98810FE0B36E5B427157B9418449CEDD641A4293C85C32700102ACEC22EBAD98ED160A5F027BD4CDA57F1F3720A12C134654DD5E73F829676495390D0E7929D6034E9C55F7D55BA658BC587988E8AF94960F6CFB8D5AF7A0021535A6E25E437D49A780698BE22AC9953949F571B85A685725F8207A2B0AE849B601AB91B159B3DF4A154C2041E776070AFC42969322380917C97510799F3149131477E16663D3174C7C1CAEA788535C6C005A64F2868631B31B66E205FD38C1D84542D0F1B578F58C9BF5A0FAEAB6AB6494893053165EAFD465FC64A0C5F8F3F9003489415899D59A543D8208C54A3166529B539228A39E87D531F3527C207EDCC1DB7FADDCF9628391879B335C707839A0DB051A8B505D7CFAD1B497499323C8686325E4792F267AAFA3F87CA60D01CB54F29202A";

        byte[] seed = Hex.decode(temp);

        NISTSecureRandom random = new NISTSecureRandom(seed, null);
        
        byte[] coins = new byte[64];
        random.nextBytes(coins);

        KyberKeyPairGenerator keyGen = new KyberKeyPairGenerator();

        keyGen.init(new KyberKeyGenerationParameters(new FixedSecureRandom(coins), KyberParameters.kyber1024));

        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
        // System.out.print("public key = ");
        // Helper.printByteArray(((KyberPublicKeyParameters) keyPair.getPublic()).getEncoded());
        assertTrue(Arrays.areEqual(Hex.decode(expectedPubKey), ((KyberPublicKeyParameters)keyPair.getPublic()).getEncoded()));

        // System.out.print("secret Key = ");
        // Helper.printByteArray(((KyberPrivateKeyParameters) keyPair.getPrivate()).getEncoded());
        assertTrue(Arrays.areEqual(Hex.decode(expectedPrivKey), ((KyberPrivateKeyParameters)keyPair.getPrivate()).getEncoded()));

        KyberKEMGenerator kemGen = new KyberKEMGenerator(random);

        SecretWithEncapsulation secretEncap = kemGen.generateEncapsulated(keyPair.getPublic());

        String expectedSharedSecret = "C9786ED936508E178D55A1208C590A10F25CFBFEB50BE4207395A8B2F8AA192E";

        // System.out.print("Shared secret = ");
        // Helper.printByteArray(secretEncap.getSecret());
        assertTrue(Arrays.areEqual(Hex.decode(expectedSharedSecret), secretEncap.getSecret()));

        String expectedCipherText = "E97436B18AE42096AE6237C8E56E1B777A9C4CAF1B20D1C40F230B45DC38F1A68013EEE84F6F5633C39E7A5548092A23B46220934C698A6DBC88149D8EE666D427E697CBF464DB1A41BBC86F1C2EF998E46E51B5D94D560109E7319AD2316FD4C2EEACFBC01DC54D8A47E33C66A82094465D1FB1C6B7BD9331BA1CE5AF1C28ADBD130FEB1C35768D388D58444700643E70262889CBFED51AD328D0E3724E63B60253445A75A96B0FBF5B580DE3D2ACE22802DF3F1B009404575745F2F7A75CAE5E1E5AD414AD363CB5DFA48F7C6ED3587278EF58EE98B144438EAA66E5CD0BA800FB9799FBF63DE47D9904039AF5722E3D7E0A3C08A0A4B62F3743E179101EDBA93B081C79ED9A065BFFF65AD71D8548EAF76ADD4C32E3BC4D6C7551FB604CEB62CCF94C8A4EE41E7362B3E66ACB86C250E61BDC8AF162F1A2D9B29403D4976C37179C9A4927CDD6BF1ACACFE4A645EB5A59919FEFF17D86F5DCC77ABC52F56E70C41197E9B8328726C3D20C9D3ACE0CBFA0A7F50C5DDB2F1507D590071B6F1D17CA84DEA7A5930DC5B70F37AD7F447447481D4F14EA2718DB1CD8E096011DD617ED56BD0B2D0AE8C51BB0FF1B052CDC9D09BC6A772FD75877F762E72E6FC39F9A8E9EBF1E3ADEFA1ED897BF81BC6751DB4D637918BAD74C6A9D5D5E5F6E512A08C3D8165B0DE8DDEDEBC5066C2C44FC5A0C97531C0EEEEFED4C5565BEE4B33DD782C7178E91F8AE7AC30B3E010EEB25F7D558F7C953602EEE903C22C2D657EB32624B1B8F854232AD6F19C298830E6A8F6FEBCA91AEC693A08BA4294D0461F55A5AD25965BC81547036121E28A20DE2E658B358B9D17EB065B0A2D1D3BB029BCEC85FCE555728FAB7A77BAA183F92FD4430DD3F1E099F23BA59E1C737A9F56BBD0236AFA079CD7D37A15E407D47B745C891364D7DB99887C4C2816875A3FCC3B4B9FA646F7819871692434FED5588BC5AA53C7B33A12D163B584F11FB07535A84AE9DACDE81D8FC77B1368CAE470797069FC7C782FA96A7FEC30BC6F0ED7D4934C00B09A629029CC17E1BC433B2C7CF35E7895908848E417C184655C8E708F803C47B3C8BA45CFEBB9BCBB933C6CB72CCFC4C27863B8F9E0FE9A2FDB186359315BE6B46B50D19900D6E890B9FC4A87B517B24909B72A1ADE60ED549E2ED500CB60FDC7642F782AFC33133E1811613049F4229C00CC734969BF673E2690C3AB63DD0E064B9D2CAE9BD218A03808D7A4ED92D1F39ECDE7F102E8D47701AFCA94C788D7FF101BF8EB022BD25CD6CD12B2710FB0EEE09E467692E6D14BAAE47C771E4D2B10927CBDE8994B023210CAE0EFDA65306B4B30C6619DFB8A7937852D92759AAE5625AE717A1608B486AE3F25CB46B78F3D04B3410B41CE829CA6C29B7E6806740F8E818A72F3C082E24782BF63D4C3FC17C011D9AE0FA2DBA4EAD828158FB40C15E0C252924B77979F8068DAD4F8EE7A7DA07306293B25E507791906692C431F23592FAA77F4F6F9F5023413E0E812DE0681372D09B07CAE884DEDBB8AC2B80347D3511E4CFCA50CD752A16593858DF1A2E6A52887D5A2F81E70E57C65FA2753478A285C3896F6272133FA40A88DDB04D7985EF70C35D7413DBD32F49478694C509F2C97D21822F20740A86DD7ABDF66D0E632A254056DF5E0E7F013BCB7DFF01E38F881CFF77F1EDD48612A2677B7D1E4E62D5A6196340E26151EEA29D8EBD9786E38721B09EC974E336F2437505EAC34DE0270C0780C6B3A89520475481409864797DA4B6ACBE848225E25C7265A4E3BE16EE8CD8A225D2FDF4C498BA35332A553FE4066D73E758653F51A8A08913E469907DA5E7BF068E4C18486D1BE273BB4C674491BFE27F94453F64048086C93AE7F96FF7505B57CF3EDAC0AA5DE3A6B06470266DBC8945E952A2A73BD7CF8524E8EA00E1D0631DCA8F658145910F7248BE8266D0F98EF7152A112F3762F7B5356161E756D7EA4FCEFD3CBC44D4E59DCDA05ACC37F90B44C62431EB7610E15375984892B769D9417FCD6781B434F4C59191A020DADD81F0928E11C010617087015A968A5EA8B52DF8BB1706BF4AC7839FA80D52CC05C499091977B29B4AEABB7B1974D1B3BC097B23F3977CB0DF44E1A20318B4642D7A67D330F45A6FA5DEB96D8DDB9EAE323E61371BB6BEF4C13771D53BFA33B40408C813D3F539A29C4CF99C1D273E8561E2C53B505436CC3C";

        assertTrue(Arrays.areEqual(Hex.decode(expectedCipherText), secretEncap.getEncapsulation()));

        KyberKEMExtractor kemExtract = new KyberKEMExtractor((KyberPrivateKeyParameters)keyPair.getPrivate());

        byte[] decryptedSharedSecret = kemExtract.extractSecret(secretEncap.getEncapsulation());

        assertTrue(Arrays.areEqual(Hex.decode(expectedSharedSecret), decryptedSharedSecret));
    }

    public void testRNG()
    {
        String temp = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
        byte[] seed = Hex.decode(temp);
        NISTSecureRandom r = new NISTSecureRandom(seed, null);
        byte[] testBytes = new byte[48];
        r.nextBytes(testBytes);

        String randBytesString = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DB505D7CFAD1B497499323C8686325E47";
        byte[] randBytes = Hex.decode(randBytesString);

        assertTrue(Arrays.areEqual(randBytes, testBytes));
    }

    public void testParameters()
        throws Exception
    {
        assertEquals(256, KyberParameters.kyber512.getSessionKeySize());
        assertEquals(256, KyberParameters.kyber768.getSessionKeySize());
        assertEquals(256, KyberParameters.kyber1024.getSessionKeySize());
    }

    public void testVectors()
        throws Exception
    {
        KyberParameters[] params = new KyberParameters[]{
            KyberParameters.kyber512,
            KyberParameters.kyber768,
            KyberParameters.kyber1024,
        };

        String[] files = new String[]{
            "kyber512.rsp",
            "kyber768.rsp",
            "kyber1024.rsp",
        };

        TestSampler sampler = new TestSampler();
        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/kyber", name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
            while ((line = bin.readLine()) != null)
            {
                line = line.trim();

                if (line.startsWith("#"))
                {
                    continue;
                }
                if (line.length() == 0)
                {
                    if (buf.size() > 0)
                    {
                        String count = (String)buf.get("count");
                        if (sampler.skipTest(count))
                        {
                            continue;
                        }
                        System.out.println("test case: " + count);

                        byte[] seed = Hex.decode((String)buf.get("seed")); // seed for Kyber secure random
                        byte[] pk = Hex.decode((String)buf.get("pk"));     // public key
                        byte[] sk = Hex.decode((String)buf.get("sk"));     // private key
                        byte[] ct = Hex.decode((String)buf.get("ct"));     // ciphertext
                        byte[] ss = Hex.decode((String)buf.get("ss"));     // session key

                        NISTSecureRandom random = new NISTSecureRandom(seed, null);
                        KyberParameters parameters = params[fileIndex];

                        byte[] coins = new byte[64];
                        random.nextBytes(coins);
                        KyberKeyPairGenerator kpGen = new KyberKeyPairGenerator();
                        KyberKeyGenerationParameters genParam = new KyberKeyGenerationParameters(new FixedSecureRandom(coins), parameters);
                        //
                        // Generate keys and test.
                        //
                        kpGen.init(genParam);
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                        KyberPublicKeyParameters pubParams = (KyberPublicKeyParameters)PublicKeyFactory.createKey(
                            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((KyberPublicKeyParameters)kp.getPublic()));
                        KyberPrivateKeyParameters privParams = (KyberPrivateKeyParameters)PrivateKeyFactory.createKey(
                            PrivateKeyInfoFactory.createPrivateKeyInfo((KyberPrivateKeyParameters)kp.getPrivate()));

                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, pubParams.getEncoded()));
                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, privParams.getEncoded()));

                        // KEM Enc
                        KyberKEMGenerator KyberEncCipher = new KyberKEMGenerator(random);
                        SecretWithEncapsulation secWenc = KyberEncCipher.generateEncapsulated(pubParams);
                        byte[] generated_cipher_text = secWenc.getEncapsulation();

                        //assertTrue(name + " " + count + ": kem_enc cipher text", Arrays.areEqual(ct, generated_cipher_text));
                        byte[] secret = secWenc.getSecret();
                        assertTrue(name + " " + count + ": kem_enc key", Arrays.areEqual(ss, 0, secret.length, secret, 0, secret.length));

                        // KEM Dec
                        KyberKEMExtractor KyberDecCipher = new KyberKEMExtractor(privParams);

                        byte[] dec_key = KyberDecCipher.extractSecret(generated_cipher_text);

                        assertTrue(name + " " + count + ": kem_dec ss", Arrays.areEqual(ss, 0, dec_key.length, dec_key, 0, dec_key.length));
                        assertTrue(name + " " + count + ": kem_dec key", Arrays.areEqual(dec_key, secret));
                        // } 
                        // catch (AssertionError e) {
                        //     System.out.println("Failed assertion error.");
                        //     System.out.println();

                        //     System.out.println();
                        //     continue;
                        // }
                    }
                    buf.clear();

                    continue;
                }

                int a = line.indexOf("=");
                if (a > -1)
                {
                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
            }
            System.out.println("testing successful!");
        }
    }

    public void testKyberRandom()
    {
        SecureRandom random = new SecureRandom();
        KyberKeyPairGenerator keyGen = new KyberKeyPairGenerator();

        keyGen.init(new KyberKeyGenerationParameters(random, KyberParameters.kyber1024));

        for (int i = 0; i != 1000; i++)
        {
            AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

            KyberKEMGenerator kemGen = new KyberKEMGenerator(random);

            SecretWithEncapsulation secretEncap = kemGen.generateEncapsulated(keyPair.getPublic());

            KyberKEMExtractor kemExtract = new KyberKEMExtractor((KyberPrivateKeyParameters)keyPair.getPrivate());

            byte[] decryptedSharedSecret = kemExtract.extractSecret(secretEncap.getEncapsulation());

            assertTrue(Arrays.areEqual(secretEncap.getSecret(), decryptedSharedSecret));
        }
    }
}