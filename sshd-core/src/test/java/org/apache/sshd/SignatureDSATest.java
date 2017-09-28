package org.apache.sshd;

import java.security.PublicKey;
import java.security.Security;

import org.apache.commons.codec.binary.Hex;
import org.apache.sshd.common.signature.SignatureDSA;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.KeyUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SignatureDSATest {

    @org.junit.Test
    public void test() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        SignatureDSA dsa = new SignatureDSA();
        byte[] K_S = Hex.decodeHex(("000000077373682d6473730000008100e29892e70f3eafba4dc396f00a10" +
                "afd43649eeceb20b386277741c1a6cddfc68e6aded7675083e1ba42197d9" +
                "80a07e080153214dc472fb861e7d80c6b3628311c1bed7016e9a16e407d0" +
                "949542f380ee36c3244f413e9e0de4d8e22faa062f93d347d855077ea80a" +
                "a0aa143f9719546fbdd4081dbab3f6c3da61308de64f3efb0000001500b2" +
                "45cf1945af96a978a26ec88b949c58d59d4e9700000081009544a23c239e" +
                "113853aeb3c51a7d3cc4d364982daf491d408b16bc97e0d1bcaa48a08f6d" +
                "5bfa8acc120832593576aa9c1d4de4fabefdede11cd6f06625795173869e" +
                "9ddcb75ed3b9b89760bffb9cb115e58365f87acc978dac9a674e6f83ea13" +
                "064db3a07319f912460c976755029f1501b8a43c7550ab635b4da90bf51c" +
                "33a90000008006407bc387fd96e269addcd91b0da7a50fb6d3842e38ac74" +
                "dbdfcf09ded98b7e458aebe629ca5e59c0a4b57ecb13dfc06e88b9a0785d" +
                "767f9e6df530521dce6fff80c8fc0fcef532c6643d0a7316b8477813d905" +
                "f746d7f5221f5b2e12d5cc184b6910ee87eeaf1c45ba7227e23cb68780d6" +
                "d04ad58c1cfd8532990bb9f15800").toCharArray());
        byte[] sig = Hex.decodeHex(("00000007" +
                "7373682d647373" +
                "00000028" +
                "5849017d595062f0ee727cb30de45580fc39c329" +
                "006d0e59539e7775fbe9da43a6126459f5ca5670").toCharArray());
        Buffer buffer = new Buffer(K_S);
        PublicKey serverKey = buffer.getRawPublicKey();
        final String keyAlg = KeyUtils.getKeyType(serverKey);
        System.out.println(keyAlg);
//        org.apache.sshd.common.util.SecurityUtils.setSecurityProvider("SUN");
        dsa.init(serverKey, null);
        dsa.verify(sig);
    }

}
