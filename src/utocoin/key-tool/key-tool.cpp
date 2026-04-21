#include <chainparams.h>
#include <chainparamsbase.h>
#include <fstream>
#include <common/args.h>
#include <key.h>
#include <key_io.h>
#include <script/parsing.h>
#include <univalue.h>
#include <util/translation.h>

const TranslateFn G_TRANSLATION_FUN{nullptr};

std::string DecodeScript(const CScript& script)
{
    std::stringstream ss;
    int witnessVersion;
    std::vector<unsigned char> program;
    if (script.IsWitnessProgram(witnessVersion, program)) {
        ss << witnessVersion << " " << HexStr(Span{program.data(), program.size()});
        return ss.str();
    }

    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    opcodetype opcode;
    std::vector<unsigned char> vchPushValue;
    bool fPrevSpace = false;
    for (; pc < pend;) {
        if (!script.GetOp(pc, opcode, vchPushValue)) {
            throw std::runtime_error("bad opcode");
        }

        if (vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE) {
            throw std::runtime_error("bad push data size");
        }

        if (fPrevSpace) {
            ss << " ";
        }
        if (opcode <= OP_PUSHDATA4) {
            if (vchPushValue.size() <= 4) {
                CScriptNum num(vchPushValue, true);
                ss << num.GetInt64();
            } else {
                ss << HexStr(Span{vchPushValue.data(), vchPushValue.size()});
            }
        } else {
            ss << GetOpName(opcode);
        }
        fPrevSpace = true;
    }
    return ss.str();
}

UniValue DumpScript(const CScript& script)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("ScriptPubKey", HexStr(Span{script.data(), script.size()}));
    result.pushKV("DecodedScript", DecodeScript(script));
    return result;
}


UniValue DumpAddress(const CTxDestination& addr)
{
    UniValue result(UniValue::VOBJ);

    std::string addr_p2pkh = EncodeDestination(addr);
    result.pushKV("Addr", addr_p2pkh);
    CScript script = GetScriptForDestination(addr);
    result.pushKV("ScriptPubKey", HexStr(Span{script.data(), script.size()}));
    result.pushKV("DecodedScript", DecodeScript(script));
    ;
    return result;
}

UniValue DumpKey(const CKey& key)
{
    UniValue vKey(UniValue::VOBJ);
    UniValue vPrivKey(UniValue::VOBJ);

    std::string wif = EncodeSecret(key);
    std::string hexPrivKey = HexStr(Span{key.data(), key.size()});
    vPrivKey.pushKV("wif", wif);
    vPrivKey.pushKV("hex", hexPrivKey);

    vKey.pushKV("PrivKey", vPrivKey);

    std::vector<unsigned char> vchRecoveryKey = ParseHex<unsigned char>(hexPrivKey);
    CKey recoveryKey;
    recoveryKey.Set(vchRecoveryKey.begin(), vchRecoveryKey.end(), true);

    if (!(key == recoveryKey)) {
        throw std::runtime_error("recover pkey failed");
    }

    UniValue vPubKey(UniValue::VOBJ);

    CPubKey pubkey = key.GetPubKey();
    vPubKey.pushKV("hex", HexStr(Span{pubkey.data(), pubkey.size()}));

    CKeyID keyid = pubkey.GetID();
    vPubKey.pushKV("hash160", HexStr(Span{keyid.data(), keyid.size()}));

    vKey.pushKV("PubKey", vPubKey);

    UniValue vXOnlyPubKey(UniValue::VOBJ);

    XOnlyPubKey xonly_pubkey = XOnlyPubKey{pubkey};
    vXOnlyPubKey.pushKV("hex", HexStr(Span{xonly_pubkey.data(), xonly_pubkey.size()}));
    std::vector<CKeyID> keyids = xonly_pubkey.GetKeyIDs();

    UniValue vXOnlyKeyIDs(UniValue::VARR);

    for (size_t i = 0; i < keyids.size(); i++) {
        std::string hexKeyID = HexStr(Span{keyids[i].data(), keyids[i].size()});
        vXOnlyKeyIDs.push_back(hexKeyID);
    }

    vXOnlyPubKey.pushKV("hash160", vXOnlyKeyIDs);
    vKey.pushKV("XOnlyPubKey", vXOnlyPubKey);

    return vKey;
}

int CreateKeySuite(std::optional<int64_t>& locktime)
{
    CKey key;
    UniValue result(UniValue::VOBJ);

    key.MakeNewKey(true);
    result.pushKV("Key", DumpKey(key));

    CPubKey pubkey = key.GetPubKey();
    CKeyID keyid = pubkey.GetID();

    if (locktime.has_value()) {
        CTxDestination p2pkh = PKHash(keyid);
        CScript script = CScript() << locktime.value() << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
        CScript p2pkhScript = GetScriptForDestination(p2pkh);
        script.insert(script.end(), p2pkhScript.begin(), p2pkhScript.end());
        result.pushKV("P2S", DumpScript(script));

        uint160 scriptHash160 = Hash160(script);

        UniValue innerScript(UniValue::VOBJ);
        innerScript.pushKV("Hash160", HexStr(Span{scriptHash160.data(), scriptHash160.size()}));
        innerScript.pushKV("DecodedScript", DecodeScript(script));

        CTxDestination p2sh = ScriptHash(script);
        UniValue vP2SH = DumpAddress(p2sh);

        vP2SH.pushKV("Script", innerScript);
        result.pushKV("P2SH", vP2SH);

        CTxDestination p2wsh = WitnessV0ScriptHash(script);
        UniValue vP2WSH = DumpAddress(p2wsh);

        innerScript.clear();
        innerScript.setObject();

        CSHA256 sha;
        sha.Write(script.data(), script.size());
        unsigned char scriptSha256[CSHA256::OUTPUT_SIZE];
        sha.Finalize(scriptSha256);

        innerScript.pushKV("Sha256", HexStr(Span{scriptSha256, CSHA256::OUTPUT_SIZE}));
        innerScript.pushKV("DecodedScript", DecodeScript(script));

        vP2WSH.pushKV("Script", innerScript);
        result.pushKV("P2WSH", vP2WSH);

    } else {
        CTxDestination p2pkh = PKHash(keyid);

        UniValue vPKH = DumpAddress(p2pkh);
        result.pushKV("P2PKH", vPKH);

        CTxDestination p2wpkh = WitnessV0KeyHash(keyid);
        UniValue vWPKH = DumpAddress(p2wpkh);

        UniValue internalScript(UniValue::VOBJ);
        CScript script = GetScriptForDestination(p2pkh);
        internalScript.pushKV("Script", HexStr(Span{script.data(), script.size()}));
        internalScript.pushKV("DecodedScript", DecodeScript(script));

        vWPKH.pushKV("Script", internalScript);

        result.pushKV("P2WPKH", vWPKH);
    }

    std::cout << result.write(2) << std::endl;
    return 0;
}

int BatchCreate(int64_t n, const std::string& key_file_path, const std::string& id_file_path)
{
    std::ofstream keys_file(key_file_path);
    std::ofstream key_ids_file(id_file_path);

    if (!keys_file) {
        std::cerr << "Open file failed: " << key_file_path << std::endl;
        return 1;
    }
    if (!key_ids_file) {
        std::cerr << "Open file failed: " << id_file_path << std::endl;
        return 1;
    }

    for (int64_t i = 0; i < n; i++) {
        CKey key;
        key.MakeNewKey(true);
        Assert(key.IsValid());

        CPubKey pubkey = key.GetPubKey();
        CKeyID keyid = pubkey.GetID();


        std::string wif = EncodeSecret(key);
        std::string hexPrivKey = HexStr(Span{key.data(), key.size()});
        std::string hash160 = HexStr(Span{keyid.data(), keyid.size()});

        keys_file << "------------------- key:" << i << " -------------------" << std::endl;
        keys_file << "wif: " << wif << std::endl;
        keys_file << "pubkey: " << HexStr(Span{pubkey.data(), pubkey.size()}) << std::endl;
        keys_file << "hex: " << hexPrivKey << std::endl;
        keys_file << "hash160: " << hash160 << std::endl;

        key_ids_file << hash160 << std::endl;
    }
    return 0;
}

int main(int argc, char* argv[])
{
    ECC_Context _;

    ArgsManager argsman;
    argsman.AddArg("-help", "Print this help message and exit (also -h or -?)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddHiddenArgs({"-h", "-?"});

    argsman.AddArg("-chain=<chain>", "Use the chain <chain> (default: main). Allowed values: " LIST_CHAIN_NAMES, ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-locktime=<locktime>", "Use the locktime <locktime> (default: None) to setup a locktime for the script", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    argsman.AddArg("-create", "create a new private key suite", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-batch=<number>", "batch create new private keys", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-key-file=<path-to-key-file>", "The path of the key file in batch mode, default is keys.txt", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-id-file=<path-to-id-file>", "The path of the key id file in batch mode, default is key-ids,txt", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    std::string error;
    if (!argsman.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }

    if (argsman.GetBoolArg("help") || argsman.GetBoolArg("h")) {
        tfm::format(std::cerr, "%s\n", argsman.GetHelpMessage());
        return EXIT_FAILURE;
    }

    ChainType chainType = argsman.GetChainType();
    SelectParams(chainType);

    std::optional<int64_t> locktime = argsman.GetIntArg("locktime");

    std::string commandList = "-create,-batch";

    bool fRunFlag = false;
    if (argsman.GetBoolArg("create")) {
        fRunFlag = true;
        return CreateKeySuite(locktime);
    }

    std::optional<int64_t> batch = argsman.GetIntArg("batch");
    if (batch.has_value() && batch.value() > 0) {
        fRunFlag = true;
        auto key_file = argsman.GetArg("key-file");
        auto id_file = argsman.GetArg("id-file");

        return BatchCreate(batch.value(),
                           key_file.has_value() ? key_file.value() : "keys.txt",
                           id_file.has_value() ? id_file.value() : "key-ids.txt");
    }

    if (!fRunFlag) {
        tfm::format(std::cerr, "The available command in %s\n", commandList);
        return EXIT_FAILURE;
    }
    return 0;
}