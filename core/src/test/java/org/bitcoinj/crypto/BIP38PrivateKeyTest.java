/*
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.crypto;

import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.BIP38PrivateKey.BadPassphraseException;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet4Params;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;

public class BIP38PrivateKeyTest {
    private static final NetworkParameters MAINNET = MainNetParams.get();
    private static final NetworkParameters TESTNET = TestNet4Params.get();

    @Test
    public void bip38testvector_noCompression_noEcMultiply_test1() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PfXN3QdWxURYFFA47Eq1rnzu4au2Aop2oKn16by3Ricd6qjjb7o8RFtpF");
        ECKey key = encryptedKey.decrypt("TestingOneTwoThree");
        assertEquals("6uLcpZm93MSx2YXkNgc3DtioYudFTHPYeykQ4RwLJxW3aUf6AQ9", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_noCompression_noEcMultiply_test2() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PfQAvPqNNMdaMkskzRF9RLc9TnxYqtKDbMWt7uqZMiViMx7Am3qKFRnFE");
        ECKey key = encryptedKey.decrypt("Satoshi");
        assertEquals("6vsG4BcN1e7H9k1xHzH7rGsQdGh6XEX9bhHt8DsgH8kX9QM1vqp", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_noCompression_noEcMultiply_test3() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PfLWy6YTK2KM2gXNXgaa44DA6pUWi6gY7Bgd6nvgDwacMszbNmzERpPqk");
        StringBuilder passphrase = new StringBuilder();
        passphrase.appendCodePoint(0x03d2); // GREEK UPSILON WITH HOOK
        passphrase.appendCodePoint(0x010400); // DESERET CAPITAL LETTER LONG I
        passphrase.appendCodePoint(0x01f4a9); // PILE OF POO
        ECKey key = encryptedKey.decrypt(passphrase.toString());
        assertEquals("6vx4nACJTAoJLrG9pSrEF1tCDTMhdnuC2CmMfE2tP2rtv9z6sev", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_compression_noEcMultiply_test1() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PfWTYuvwCVnkmtetL4h7unww9XJtMNNwneXQYe96qYuzuerXNwVj5hhqG");
        ECKey key = encryptedKey.decrypt("TestingOneTwoThree");
        assertEquals("6uFZt3uSiKP29cj1X4wymWa1AQzpVbvZKhG92KHnSnwdmwfb8YZ", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_compression_noEcMultiply_test2() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PfMXBsZbkfnyNBRuVF3FKa7rnqJoW4e8UrevazHmTtDw621S9e1GmoKNb");
        ECKey key = encryptedKey.decrypt("Satoshi");
        assertEquals("6w465J4TFFpQepzEE8BdQdbavKCie34WGV19PURsPa5hnE18e5t", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_ecMultiply_noCompression_noLotAndSequence_test1() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PfU6AZPbBFfguCSo3PaxrWLz9MNbVzEFQLBstvBMWvPX5irTGbGYARaxH");
        ECKey key = encryptedKey.decrypt("TestingOneTwoThree");
        assertEquals("6vaUDKzhoKLXpuq2oSZuLiBcwSDtgxbuMNpUrrSRXfiNc9JeTkW", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_ecMultiply_noCompression_noLotAndSequence_test2() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PfWy6Vr8gXZiYss2vTENBMAJnQj4Hbs1b7uhE2sQop62SdcpjfkJWooGd");
        ECKey key = encryptedKey.decrypt("Satoshi");
        assertEquals("6uK3c4JV6AmtzqHvkpxZqmsaowkfeaJ1Qj5uBZdD81TpK9Bj5Wd", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_ecMultiply_noCompression_lotAndSequence_test1() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PfWPu3RVs2JTyJXnQEbiDQ8CU5QRoWc4VtjYaPp7KSefd4RXXxCsR3JWz");
        ECKey key = encryptedKey.decrypt("MOLON LABE");
        assertEquals("6vHKczVmWJUUygAVr1LEWXhJDXPMZbm4Fq1j7i4xZS7zrdrchJR", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_ecMultiply_noCompression_lotAndSequence_test2() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PfLNvLvW5hAX68yhpNwjMCoYk8GWjUAjjKinifxPRvcyii1VSwZTgUWGH");
        ECKey key = encryptedKey.decrypt("ΜΟΛΩΝ ΛΑΒΕ");
        assertEquals("6vY6y3iQZ9f4uiw6tnMUmdpmgz4mz1WLEuFw6TV64CNeUoaaByA", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bitcoinpaperwallet_testnet() throws Exception {
        // values taken from bitcoinpaperwallet.com
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(TESTNET,
                "6PfNE5zEBc7hYVg7dFGpDefkViqJnKjuzbGYxYpQjfpTjXVAqBDEbiBWC1");
        ECKey key = encryptedKey.decrypt("password");
        assertEquals("92xcGLsqZxWWuGEcne3Ci8Rcf9GKpanNUB3CgpfsWd5miqZHoDk", key.getPrivateKeyEncoded(TESTNET)
                .toString());
    }

    @Test
    public void bitaddress_testnet() throws Exception {
        // values taken from bitaddress.org
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(TESTNET,
                "6PfTzoonPxFXcyPU6F2AtMQbqp9TTGeCNcMConopzmwut4DMWhpGdHaNCa");
        ECKey key = encryptedKey.decrypt("password");
        assertEquals("92RzBMkKQ5ALzDowfFjHsEDyYCVk3eUyvJUacwWNQUfGi6wdjPJ", key.getPrivateKeyEncoded(TESTNET)
                .toString());
    }

    @Test(expected = BadPassphraseException.class)
    public void badPassphrase() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PfTwMdGgY2ogcquhvWRwcDbyRbD8dtj3NzsPiq8wGxmcfLWrHLXR2KccG");
        encryptedKey.decrypt("BAD");
    }

    @Test(expected = AddressFormatException.InvalidDataLength.class)
    public void fromBase58_invalidLength() {
        String base58 = Base58.encodeChecked(1, new byte[16]);
        BIP38PrivateKey.fromBase58(null, base58);
    }

    @Test
    public void testJavaSerialization() throws Exception {
        BIP38PrivateKey testKey = BIP38PrivateKey.fromBase58(TESTNET,
                "6PfQKLMjyApgdh7adsiX9GqH4WvfmQ4KAiJ2Tnt3dXwpY1L2UNss2mMoXp");
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        new ObjectOutputStream(os).writeObject(testKey);
        BIP38PrivateKey testKeyCopy = (BIP38PrivateKey) new ObjectInputStream(
                new ByteArrayInputStream(os.toByteArray())).readObject();
        assertEquals(testKey, testKeyCopy);

        BIP38PrivateKey mainKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PfQKLMjyApgdh7adsiX9GqH4WvfmQ4KAiJ2Tnt3dXwpY1L2UNss2mMoXp");
        os = new ByteArrayOutputStream();
        new ObjectOutputStream(os).writeObject(mainKey);
        BIP38PrivateKey mainKeyCopy = (BIP38PrivateKey) new ObjectInputStream(
                new ByteArrayInputStream(os.toByteArray())).readObject();
        assertEquals(mainKey, mainKeyCopy);
    }

    @Test
    public void cloning() throws Exception {
        BIP38PrivateKey a = BIP38PrivateKey.fromBase58(TESTNET, "6PfQKLMjyApgdh7adsiX9GqH4WvfmQ4KAiJ2Tnt3dXwpY1L2UNss2mMoXp");
        // TODO: Consider overriding clone() in BIP38PrivateKey to narrow the type
        BIP38PrivateKey b = (BIP38PrivateKey) a.clone();

        assertEquals(a, b);
        assertNotSame(a, b);
    }

    @Test
    public void roundtripBase58() throws Exception {
        String base58 = "6PfQKLMjyApgdh7adsiX9GqH4WvfmQ4KAiJ2Tnt3dXwpY1L2UNss2mMoXp";
        assertEquals(base58, BIP38PrivateKey.fromBase58(MAINNET, base58).toBase58());
    }
}
