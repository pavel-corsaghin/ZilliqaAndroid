package com.firestack.laksaj.account;

import com.firestack.laksaj.jsonrpc.HttpProvider;
import com.firestack.laksaj.transaction.Transaction;
import com.firestack.laksaj.transaction.TransactionFactory;
import org.junit.Test;

import java.io.IOException;

import static com.firestack.laksaj.account.Wallet.pack;

public class WalletTest {
    @Test
    public void sign() throws IOException {
        Wallet wallet = new Wallet();
        String address = wallet.addByPrivateKey("e19d05c5452598e24caad4a0d85a49146f7be089515c905ae6a19e8a578a6930");
        System.out.println("from address: " + address);

        Transaction transaction = Transaction.builder()
                .version(String.valueOf(pack(2, 8)))
                .toAddr("4baf5fada8e5db92c3d3242618c5b47133ae003c".toLowerCase())
                .senderPubKey("0246e7178dc8253201101e18fd6f6eb9972451d121fc57aa2a06dd5c111e58dc6a")
                .amount("10000000000000")
                .gasPrice("1000000000")
                .gasLimit("1")
                .code("")
                .data("")
                .provider(new HttpProvider("https://api.zilliqa.com/"))
                .build();
        transaction = wallet.sign(transaction);
        System.out.println("signature is: " + transaction.getSignature());
        HttpProvider.CreateTxResult result = TransactionFactory.sendTransaction(transaction);
        System.out.println(result);
    }


}