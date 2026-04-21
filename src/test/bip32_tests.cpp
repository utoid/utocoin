// Copyright (c) 2013-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <clientversion.h>
#include <key.h>
#include <key_io.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <string>
#include <vector>

namespace {

struct TestDerivation {
    std::string pub;
    std::string prv;
    unsigned int nChild;
};

struct TestVector {
    std::string strHexMaster;
    std::vector<TestDerivation> vDerive;

    explicit TestVector(std::string strHexMasterIn) : strHexMaster(strHexMasterIn) {}

    TestVector& operator()(std::string pub, std::string prv, unsigned int nChild) {
        vDerive.emplace_back();
        TestDerivation &der = vDerive.back();
        der.pub = pub;
        der.prv = prv;
        der.nChild = nChild;
        return *this;
    }
};

TestVector test1 =
  TestVector("000102030405060708090a0b0c0d0e0f")
    ("upub57Wa4MvRPNyAhzxKw1WfftuLKMiCWuDZefryEdU2JCzjgbWHqJCxXM4GVQGUSXn55srUm189Mf4uER1BVZxyhNQZ56pbiUoAzvK54VEYrWu",
     "uprv8tXDerPXZ1QsVWsrpyyfJkxbmKsi7SViHSwNSF4QjsTkooB9HkthyYjne8dAveN1ALxYG46ziMibRtp3CL8L5LQUHQ6NYxHaEoiL29kHzK1",
     0x80000000)
    ("upub59mz45DtUe69rc638mPJYw1SeBGYtyhaLHHsCir9GQC23soUFXk3eVQgGfqBBqgc6693dEfa6J8zCoyKSbhMmFsHGjcrdnhPWrSdN8uUxKb",
     "uprv8vndeZgzeGXre81a2jrJBo4i69S4VWyiy4NGQLSXi4f3B5UKhzRo6h6CRPyWLMjxsPrEdMRs6iZU9eqkqvQWsQUzMGmWnuzTwpMBTQMruPL",
     1)
    ("upub5Bx7FrmmsLyDh48Us2HB9fu6hZFeu1RsGbxhnzcxD2zEHRJbyLAMc4JugkHkbnPx3om6Qf7gCtdTo7i8uvsFSuhDZwTi7Rhf9ayQf4yA6iv",
     "uprv8xxkrMEt2yQvUa41kzkAnXxN9XRAVYi1uP36zcDLehTFQcyTRnr74FzRqTAZwHX1KUbvSB2JBRWtHbMyyGCVeZyRs3jErfmKccfYzJj6p51",
     0x80000002)
    ("upub5EZPJPbdaDpdZDva7cgYWfwEvi8BAZ1rc9CP3Kv7NuMfhGVin5znWVrqEmUb3eqGQKrq236HaqCSFSrRd2QnWMr49qRrCNmLsGtYkKXxHdo",
     "uprv91a2tt4jjrGLLjr71b9Y9XzWNgHgm6J1EvGnEwWVpZpgpUAaEYgXxhYMPVPBuX2VpwdK2dyDbqLnWo6jZH7gmfR6DfHo1c1GDtQmcugGzU9",
     2)
    ("upub5Gnn8piakhVcdhQHostdQB6Z1XQuo9L43d5gJHSahLvH4N85qrh9i5Kkv6TyTSyzsdz1A3aEda6YosCRiKqzDxKK4cz32ZfAsxoPu22PVqK",
     "uprv93oRjKBgvKwKRDKphrMd339pTVaRPgcCgQA5Vu2y91PJBZnwJKNuAH1H4oneNBRvtjm1eZCnWenwyz1Bkhf2y418cuNtZgpyNrsw8PMvadm",
     1000000000)
    ("upub5JWYcWKpspspA3BjvRTMht6YokzDce95qsUEYZpiuRJmmVXUNGwoyBUpYvNvJi4iMLGYfPW3Amo9QHbSpBLq5DURwAQ7q3EogvRK9ATDZmi",
     "uprv95XCCznw3TKWwZ7GpPvMLk9pFj9jDBREUeYdkBR7M5mnthCKpjdZRPALhfZrH6Z1W9AGRvBjMhL4zA1ZHmfm61efxQ97gbagfCSHsXKwPTK",
     0);

TestVector test2 =
  TestVector("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
    ("upub57Wa4MvRPNyAhcTf3Aax86d6ZYrdCXUPLFehXaCrGb7byaXV1SytxFDrqWMT9n92zS6GffnJkja9xCjQckt8qHQVw324YyHqKHzBLS1ks3g",
     "uprv8tXDerPXZ1QsV8PBw93wkxgN1X28o4kXy2j6jBoEiFad6nCLTufeQSuNzCQE79v6QPhy1LZSzTknXRY9EkX2ghjEjpAchJCJp4LZP7DXwhm",
     0)
    ("upub5AnKL5cNsPoFDt3xAwxqBu2cvWbsuVxftRQ4hPEJLzyZfYyTaiKy75o7QyKLws9UCkaSXtn49pR87NA6VuaZAt4nD5kjTKSDSn6qmgmi7q2",
     "uprv8wnxva5V32Ex1PyV4vRppm5tNUmPW3EpXCUTtzpgnfSankeK3B1iZHUdZhg2kDkvp3wnuLyBRdAuswAxo325cvtdjzag5nN3wUF7kVrJ58T",
     0xFFFFFFFF)
    ("upub5BwNagduFHyMPkG8bPxUfEiBKFpnSz8MyaUbcn94zjjx7rCvCbkHK9ai2MZThbkZzGVzBjdfT2qin32SGp4fu2XQkANnp3hEKANScVz7qSC",
     "uprv8xx2BB71QvR4BGBfVNRUJ6mSmDzJ3XQWcMYzpPjTSQCyF3smf4S2mMGEB4A1UUVQiHGggNApUdg2KAujXQdDCELCAip1rJ6JjFaeWuJAd3U",
     1)
    ("upub5EkLzhcqQwGYVMwGf473dBeQenhHZB3dJ1yTTqoQJd6Png55W7GzD3y5s9kbVUSraSxY2Niu6A9YrqHTBiVdAMzKLSae2b8SEw3PrtkTK7z",
     "uprv91kzbC5waZiFGsroZ2a3G3hg6kro9iKmvo3rfTPnkHZQusjvxZxjfFec1rMdWBh72EdPRfFCtBMEdsgtaJ9bCi9VJVLphQ4hD41NzaA6PSS",
     0xFFFFFFFE)
    ("upub5FvNufZC2LEFnKAsPXvazhLbZXAec9g8KihLzZVp9PMeF2Q1bnCzjaLBVot6gqyJXtcApsnc8mUQWUSqsbc8sigmcLu8atDr7A7yPpHmk2w",
     "uprv92w2WA2JBxfxZq6QHWPadZPs1VLACgxGxVmkCB6Cb3pfNE4s4EtkBn1heZ628c5PZov5jV2CGYvpSznG6F45tYpf8Rt8qc6KYe1u4JyXzn6",
     2)
    ("upub5HHQs6mhYWYVXaMm7c4GySiZxahkrUbCytKEQLrJnBDEKDjamR8kv9HBaCxNpRL13wpQ6oJ22UVPzuWLhhJ3ByYMFWjDXFWanTKA4VcNPQT",
     "uprv94J4TbEoi8zCK6HJ1aXGcJmqQYsGT1sMcfPdbxShDqgFSRQSDspWNLxhixm2HdATc7mp2Ef1iemWVYfmpZRJwXZNwHPdu2E3F1MT8uPkBrU",
     0);

TestVector test3 =
  TestVector("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")
    ("upub57Wa4MvRPNyAgfupZZ5kL5t8SCBixPdf3bRFvsEQYHCPwpkkfbDruWTPKVtRyNigAWr8VffK9QQ1PWNKTTvaFd4e4GvHHXjg71Vsrv5o9ug",
     "uprv8tXDerPXZ1QsUBqMTXYjxwwPtAMEYvuogNVf8UpnywfR52Rc83ucMi8uUC8Q4B9RV6NiaGFYttVVt59TUBfTUBEVG6jFtjYH6mzv35j6MMW",
      0x80000000)
    ("upub59smoKkZ4kLWtD1DnhRFPLdo8Yo77F3ZT5fCk6vFUb7mCqtDF5ziyyF6dDiwhjKRMtLyGdR3zMbW1yJfPhrkpsLajNsAqPEUbBrnXMLXLzz",
     "uprv8vtRPpDfENnDfivkgftF2Ch4aWxchnKi5rjbwiWdvFanL3Z4hYgUSAvcmxUkQ8ULwF28bD3RYd7xXcnc3QFDDwS7hEeJdtp6DnxZzXT9o6S",
      0);

TestVector test4 =
  TestVector("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678")
    ("upub57Wa4MvRPNyAijRPQHSZ8qM24Rmtse3QHj7fJbuzQp35nia5sVpd7j1V1d96zpJjk3ygeLtW6BAkCP9SsfwVLUvYphDMqqhV1cB6wnmkwAF",
     "uprv8tXDerPXZ1QsWFLvJFuYmhQHWPwQUBKYvWC4WDWNrUW6uvEwKxWNZvh1AMQX4uYc4ZLLgT8gqDhGX5mk8GvNYztsmLbHwcRwNus4oGAnHxa",
     0x80000000)
    ("upub5AfgSk35m95cMcSX2cNL9ESnWMfAawZx32jKea5y4G74HFdCRqFMFmgqBDQs2SfsA9k3bPH7h76zjJqWaTPtRnyas1eKiens4Qj9kAN9LBC",
     "uprv8wgL3EWBvmXK98N3vaqKn6W3xKpgBUr6fooirBgMVva5QTJ3tHw6hyNMKuKm7iiy2YMnD2Jv9foMTjxqjeb1Zdmocity9XswNAtsY8nmgj4",
     0x80000001)
    ("upub5CoN6jS6Gs8D2mJAAtHEF72dgHqF5sGkgxn9RKcAiTCW4LwiJKj4Utei5ABPsdJYjwMQVADE9ZSyhoAR34D395uxCoVNgPGovq63oih12xr",
     "uprv8yp1hDuCSVZupHDh4rkDsy5u8FzkgQYuKjrYcwCZA7fXBYcZknQow6LEDsHrB7ko7JktPd8svJuEAhnZ8aY8r2F2s4bzFa8GDrSZdes3TGP",
     0);

const std::vector<std::string> TEST5 = {
    "upub57Wa4MvRPNyAgernS3ATpEMjMH6dHJ1xEwSdnjWyp9S9ZVEpaesN8Vv42iK4BQ7ppHgZMi5zYaQRN9KUnYKYGXwKAmtuS9Xc89M9VmzFoLj",
    "uprv8tXDerPXZ1QsUAnKL1dTT6QzoFG8sqJ6siX2zM7NFouAggug37Z7ahbaBeaeQV5ry8vbxeUWM8rsGaZtR6g3EFfM5ZaUMdnb1bzojMJF2YA",
    "upub57Wa4MvRPNyAgernS3ATpEMjMH6dHJ1xEwSdnjWyp9S9ZVEpaesN8Vv42r62tKuxDzPTtzQpAttRBRiaSznQsMJpKLBLQkHC6mNhUB94fmm",
    "uprv8tXDerPXZ1QsUAnKL1dTT6QzoFG8sqJ6siX2zM7NFouAggug37Z7ahbaBewko9mMpFwTzYHtW98xZzAnZLHs7VieoKrxZRU9AuVTi7QPv1n",
    "upub57Wa4MvRPNyAgernS3ATpEMjMH6dHJ1xEwSdnjWyp9S9ZVEpaesN8Vv42kFoMdZrfiMnVXfhTA2RKTvFhewFvEnBxQy1gJDW7oMXzNFFXtR",
    "uprv8tXDerPXZ1QsUAnKL1dTT6QzoFG8sqJ6siX2zM7NFouAggug37Z7ahbaBZ7XGTRGFyunb5YmnQGxi2NTozSiAPC2SQedpyQTBwUJEMUsRew",
    "uprv8tXeUascx6sAYNtEzGtWdXqEMg8dd82FMza7gj9fPHX8t236ARsn39idc5gbC5JH39D5kwF5BvDajgEMggMXbVF56nKWcvbp749dW5oqgC4",
    "upub57Wzt6QWnURTkrxi6JRWzfmxuhy82ak6jDViV7ZGwd47kpNEhyC2ax37TQEjbWZW1TM8AmsSKzAwrzaM6Zh84v9S3adqF4UtrEZmFrvjGYs",
    "uprv8tXDerPXcoS2KpmaUGAxit6cE6shQgifGRBYknEBm9x4sqinNLkNAPdouiB5sVdhvTR9XfaBtTQtuP3DeZ9jMHpNSdA3gjnEE6i5CLtFHxz",
    "upub57Wa4MvRTAzKYJr3aHhy623Ln8iBp9SWde79ZAdoKVV3ke3vut4ciBxHm2jEGvtvtmZBwWCZ2XNG2hPD4SVKpiijPRUNJsfJyH8Cx6PAWB3",
    "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
    "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
    "uprv8tXDerPXZ1QsUAnKL1dTT6QzoFG8sqJ6siX2zM7NFouAggug37Z7ahbaBXAn6DyEQZEZTFy4spexkhmgtspzWgM9emaXapiZCHTuiMdznQm",
    "uprv8tXDerPXZ1QsUAnKL1dTT6QzoFG8sqJ6siX2zM7NFouAggug37Z7ahbaBZ7XGTRGFyunb5YmnQGxi2NPH85odMwEyhPea7h8VeSvSXE9sAP",
    "upub57Wa4MvRPNyAgernS3ATpEMjMH6dHJ1xEwSdnjWyp9S9ZVEpaesN8Vv42nCYXs1tX931dMFQMjeRGnX2cmYyZwd4k437vSuQ7TMvUP8A8tu",
    "uprv7tXDerPXZ1QsVWsrpyyfJkxbmKsi7SViHSwNSF4QjsTkooB9HkthyYjne8dAveN1ALxYG46ziMibRtp3CL8L5LQUHQ6NYxHaEoiL29kHzK1"
};

void RunTest(const TestVector& test)
{
    std::vector<std::byte> seed{ParseHex<std::byte>(test.strHexMaster)};
    CExtKey key;
    CExtPubKey pubkey;
    key.SetSeed(seed);
    pubkey = key.Neuter();
    for (const TestDerivation &derive : test.vDerive) {
        unsigned char data[74];
        key.Encode(data);
        pubkey.Encode(data);

        // Test private key
        BOOST_CHECK(EncodeExtKey(key) == derive.prv);
        BOOST_CHECK(DecodeExtKey(derive.prv) == key); //ensure a base58 decoded key also matches

        // Test public key
        BOOST_CHECK(EncodeExtPubKey(pubkey) == derive.pub);
        BOOST_CHECK(DecodeExtPubKey(derive.pub) == pubkey); //ensure a base58 decoded pubkey also matches

        // Derive new keys
        CExtKey keyNew;
        BOOST_CHECK(key.Derive(keyNew, derive.nChild));
        CExtPubKey pubkeyNew = keyNew.Neuter();
        if (!(derive.nChild & 0x80000000)) {
            // Compare with public derivation
            CExtPubKey pubkeyNew2;
            BOOST_CHECK(pubkey.Derive(pubkeyNew2, derive.nChild));
            BOOST_CHECK(pubkeyNew == pubkeyNew2);
        }
        key = keyNew;
        pubkey = pubkeyNew;
    }
}

}  // namespace

BOOST_FIXTURE_TEST_SUITE(bip32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bip32_test1) {
    RunTest(test1);
}

BOOST_AUTO_TEST_CASE(bip32_test2) {
    RunTest(test2);
}

BOOST_AUTO_TEST_CASE(bip32_test3) {
    RunTest(test3);
}

BOOST_AUTO_TEST_CASE(bip32_test4) {
    RunTest(test4);
}

BOOST_AUTO_TEST_CASE(bip32_test5) {
    for (const auto& str : TEST5) {
        auto dec_extkey = DecodeExtKey(str);
        auto dec_extpubkey = DecodeExtPubKey(str);
        BOOST_CHECK_MESSAGE(!dec_extkey.key.IsValid(), "Decoding '" + str + "' as uprv should fail");
        BOOST_CHECK_MESSAGE(!dec_extpubkey.pubkey.IsValid(), "Decoding '" + str + "' as upub should fail");
    }
}

BOOST_AUTO_TEST_CASE(bip32_max_depth) {
    CExtKey key_parent{DecodeExtKey(test1.vDerive[0].prv)}, key_child;
    CExtPubKey pubkey_parent{DecodeExtPubKey(test1.vDerive[0].pub)}, pubkey_child;

    // We can derive up to the 255th depth..
    for (auto i = 0; i++ < 255;) {
        BOOST_CHECK(key_parent.Derive(key_child, 0));
        std::swap(key_parent, key_child);
        BOOST_CHECK(pubkey_parent.Derive(pubkey_child, 0));
        std::swap(pubkey_parent, pubkey_child);
    }

    // But trying to derive a non-existent 256th depth will fail!
    BOOST_CHECK(key_parent.nDepth == 255 && pubkey_parent.nDepth == 255);
    BOOST_CHECK(!key_parent.Derive(key_child, 0));
    BOOST_CHECK(!pubkey_parent.Derive(pubkey_child, 0));
}

BOOST_AUTO_TEST_SUITE_END()
