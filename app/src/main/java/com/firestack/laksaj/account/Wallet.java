package com.firestack.laksaj.account;

import com.firestack.laksaj.crypto.KeyTools;
import com.firestack.laksaj.crypto.Schnorr;
import com.firestack.laksaj.crypto.Signature;
import com.firestack.laksaj.jsonrpc.HttpProvider;
import com.firestack.laksaj.transaction.Transaction;
import com.firestack.laksaj.transaction.TxParams;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;


/**
 * all address should be upper case
 */
public class Wallet {
    private HttpProvider provider;
    private Account defaultAccount;

    public Wallet() {
        provider = new HttpProvider("https://api.zilliqa.com/");
    }


    public String addByPrivateKey(String privateKey) {
        defaultAccount = new Account(privateKey);
        return defaultAccount.getAddress();
    }

    public String addByKeyStore(String keystore, String passphrase) throws Exception {
        defaultAccount= Account.fromFile(keystore, passphrase);
        return defaultAccount.getAddress();
    }


    public Transaction sign(Transaction transaction) {
        if (defaultAccount == null) {
            throw new IllegalArgumentException("This wallet has no default account.");
        }

        return this.signWith(transaction, this.defaultAccount);

    }

    public Transaction signWith(Transaction tx, Account signer) {
        HttpProvider.BalanceResult result;

        if (tx.getNonce() == null || tx.getNonce().isEmpty()) {
            try {
                result = this.provider.getBalance(signer.getAddress());
                tx.setNonce(String.valueOf(Integer.valueOf(result.getNonce()) + 1));
            } catch (IOException e) {
                throw new IllegalArgumentException("cannot get nonce", e);
            }
        }
        tx.setSenderPubKey(signer.getPublicKey());
        byte[] message = tx.bytes();
        Signature signature = Schnorr.sign(signer.getKeys(), message);
        tx.setSignature(signature.toString().toLowerCase());
        return tx;
    }

    public static int pack(int a, int b) {
        return (a << 16) + b;
    }

}
