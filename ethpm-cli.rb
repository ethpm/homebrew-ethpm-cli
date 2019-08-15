class EthpmCli < Pandoc < Formula
  include Language::Python::Virtualenv

  desc "CLI tool for ethPM ecosystem."
  homepage "https://github.com/ethereum/ethpm-cli"
  url "https://files.pythonhosted.org/packages/0c/44/5604f29ec16f33ebc2bd20c57b9dc6e612c6ee3a2ef6c27a3903517aba36/ethpm-cli-0.1.0a3.tar.gz"
  sha256 "f9f94c30f2cfc63a5ddce7a3aaa1dbd5ddbafc0f1cb21293aa07f8f647562353"

  depends_on "python3"

  resource "asn1crypto" do
    url "https://files.pythonhosted.org/packages/fc/f1/8db7daa71f414ddabfa056c4ef792e1461ff655c2ae2928a2b675bfed6b4/asn1crypto-0.24.0.tar.gz"
    sha256 "9d5c20441baf0cb60a4ac34cc447c6c189024b6b4c6cd7877034f4965c464e49"
  end

  resource "attrdict" do
    url "https://files.pythonhosted.org/packages/3f/72/614aae677d28e81a5bf830fadcf580803876ef76e0306902d3ca5790cd9a/attrdict-2.0.1.tar.gz"
    sha256 "35c90698b55c683946091177177a9e9c0713a0860f0e049febd72649ccd77b70"
  end

  resource "base58" do
    url "https://files.pythonhosted.org/packages/c7/59/610af520e9f4d1b28c975bece4768d700884e38929e7ba0dcb25c9f6f87c/base58-1.0.3.tar.gz"
    sha256 "9a793c599979c497800eb414c852b80866f28daaed5494703fc129592cc83e60"
  end

  resource "certifi" do
    url "https://files.pythonhosted.org/packages/c5/67/5d0548226bcc34468e23a0333978f0e23d28d0b3f0c71a151aef9c3f7680/certifi-2019.6.16.tar.gz"
    sha256 "945e3ba63a0b9f577b1395204e13c3a231f9bc0223888be653286534e5873695"
  end

  resource "cffi" do
    url "https://files.pythonhosted.org/packages/93/1a/ab8c62b5838722f29f3daffcc8d4bd61844aa9b5f437341cc890ceee483b/cffi-1.12.3.tar.gz"
    sha256 "041c81822e9f84b1d9c401182e174996f0bae9991f33725d059b771744290774"
  end

  resource "chardet" do
    url "https://files.pythonhosted.org/packages/fc/bb/a5768c230f9ddb03acc9ef3f0d4a3cf93462473795d18e9535498c8f929d/chardet-3.0.4.tar.gz"
    sha256 "84ab92ed1c4d4f16916e05906b6b75a6c0fb5db821cc65e70cbd64a3e2a5eaae"
  end

  resource "cryptography" do
    url "https://files.pythonhosted.org/packages/c2/95/f43d02315f4ec074219c6e3124a87eba1d2d12196c2767fadfdc07a83884/cryptography-2.7.tar.gz"
    sha256 "e6347742ac8f35ded4a46ff835c60e68c22a536a8ae5c4422966d06946b6d4c6"
  end

  resource "cytoolz" do
    url "https://files.pythonhosted.org/packages/23/0d/14181131b886eee3bbc6c07c2e7469bd1d764c429644824a7dc3f8628a98/cytoolz-0.10.0.tar.gz"
    sha256 "ed9f6a07c2bac70d6c597df360d0666d11d2adc90141d54c5c2db08b380a4fac"
  end

  resource "eth-abi" do
    url "https://files.pythonhosted.org/packages/bc/fa/aac577e85e31f42203f68abcc920b5162ff58037cb13e440dee468679889/eth-abi-2.0.0.tar.gz"
    sha256 "21d6cf068a134926bf62606fb10ca39499c6f02c881ca5b78f8b745f21da23a1"
  end

  resource "eth-account" do
    url "https://files.pythonhosted.org/packages/43/fd/ec0a6dca39410e56b94be0ef6b1c6ed79e05fed7935feae19419b109f4fb/eth-account-0.4.0.tar.gz"
    sha256 "fa8308c1d280cfde28455d8c031c3a048c8811e502e750ec0d2cff76988dcd0b"
  end

  resource "eth-bloom" do
    url "https://files.pythonhosted.org/packages/22/a5/22dc06a087499f935bcaa3c59886ac84cd78c12754c91bdcae9c6e59ede3/eth-bloom-1.0.3.tar.gz"
    sha256 "89d415710af1480683226e95805519f7c79b7244a3ca8d5287684301c7cee3de"
  end

  resource "eth-hash" do
    url "https://files.pythonhosted.org/packages/c7/f7/b7a29f683aa180fe70c070cc07a6750647e92d8ecca57c8cfa3f4f2318f2/eth-hash-0.2.0.tar.gz"
    sha256 "499dc02d098f69856d1a6dd005529c16174157d4fb2a9fe20c41f69e39f8f176"
  end

  resource "eth-keyfile" do
    url "https://files.pythonhosted.org/packages/0b/fe/e2e29b7a715e8ee5fdf51b7394dcea2fe46e6b4be20a037ef0963d867666/eth-keyfile-0.5.1.tar.gz"
    sha256 "939540efb503380bc30d926833e6a12b22c6750de80feef3720d79e5a79de47d"
  end

  resource "eth-keys" do
    url "https://files.pythonhosted.org/packages/85/e9/dfef9afd660748778b8a0548088989c302550af1eb2e2aa8dcbcf8f0d134/eth-keys-0.2.4.tar.gz"
    sha256 "e15a0140852552ec3eb07e9731e23d390aea4bae892022279af42ce32e9c2620"
  end

  resource "eth-rlp" do
    url "https://files.pythonhosted.org/packages/e5/cf/8b60f64771b411629d3e71a094284320c1453fdb3a8496b3cea6853a1060/eth-rlp-0.1.2.tar.gz"
    sha256 "05d8456981d85e16a9afa57f2f2c3356af5d1c49499cc8512cfcdc034b90dde5"
  end

  resource "eth-tester" do
    url "https://files.pythonhosted.org/packages/4c/b5/4f2e2982ab68aebadb4c7a1f18791fa713189de1ea111c94f3a813879dd8/eth-tester-0.1.0b39.tar.gz"
    sha256 "771ccb903671b45228ce4df6587ae5d7449afa0a269e29c45a1217eafe2bb8aa"
  end

  resource "eth-typing" do
    url "https://files.pythonhosted.org/packages/86/ae/5a7e54a0e0c6deed7aeeff351fc09366ea47d3a904ed4d86b9e9800b2535/eth-typing-2.1.0.tar.gz"
    sha256 "164d5fb164636b62a5729557953edfadc91e4f1b055cd591cace24913a917764"
  end

  resource "eth-utils" do
    url "https://files.pythonhosted.org/packages/e9/12/a6ac53e69cef5ce3b1145878a3c3b15dce5426dec31082d98185bce0d165/eth-utils-1.6.2.tar.gz"
    sha256 "025a560a42f03db6c9484f5e6ecfdfb4d2f4652bc918092341fee9930907417f"
  end

  resource "hexbytes" do
    url "https://files.pythonhosted.org/packages/6c/96/c76cd573e7c3e38af32aa3e4ee9d9103efe33847b72f0507ac6d7a824307/hexbytes-0.2.0.tar.gz"
    sha256 "9e8b3e3dc4a7de23c0cf1bb3c3edfcc1f0df4b78927bad63816c27a027b8b7d1"
  end

  resource "idna" do
    url "https://files.pythonhosted.org/packages/ad/13/eb56951b6f7950cadb579ca166e448ba77f9d24efc03edd7e55fa57d04b7/idna-2.8.tar.gz"
    sha256 "c357b3f628cf53ae2c4c05627ecc484553142ca23264e593d327bcde5e9c3407"
  end

  resource "ipfshttpclient" do
    url "https://files.pythonhosted.org/packages/bd/76/ec048dfcdf182d04cb1e7a1a1d23018fccc4c8eb6cca5a43c4edbc39262d/ipfshttpclient-0.4.12.tar.gz"
    sha256 "0a199a1005fe44bff9da28b5af4785b0b09ca700baac9d1e26718fe23fe89bb7"
  end

  resource "jsonschema" do
    url "https://files.pythonhosted.org/packages/58/b9/171dbb07e18c6346090a37f03c7e74410a1a56123f847efed59af260a298/jsonschema-2.6.0.tar.gz"
    sha256 "6ff5f3180870836cae40f06fa10419f557208175f13ad7bc26caa77beb1f6e02"
  end

  resource "lru-dict" do
    url "https://files.pythonhosted.org/packages/00/a5/32ed6e10246cd341ca8cc205acea5d208e4053f48a4dced2b1b31d45ba3f/lru-dict-1.1.6.tar.gz"
    sha256 "365457660e3d05b76f1aba3e0f7fedbfcd6528e97c5115a351ddd0db488354cc"
  end

  resource "multiaddr" do
    url "https://files.pythonhosted.org/packages/f0/84/c9e74808cd3dfb594e13fab7606513607f9d94de1d1ad09879f9a49d2d7f/multiaddr-0.0.8.tar.gz"
    sha256 "2faec68b479945fe6b48dd2dc1f8bcccf939aa148836e3a1ab806d6c75db1238"
  end

  resource "mypy_extensions" do
    url "https://files.pythonhosted.org/packages/c2/92/3cc05d1206237d54db7b2565a58080a909445330b4f90a6436302a49f0f8/mypy_extensions-0.4.1.tar.gz"
    sha256 "37e0e956f41369209a3d5f34580150bcacfabaa57b33a15c0b25f4b5725e0812"
  end

  resource "netaddr" do
    url "https://files.pythonhosted.org/packages/0c/13/7cbb180b52201c07c796243eeff4c256b053656da5cfe3916c3f5b57b3a0/netaddr-0.7.19.tar.gz"
    sha256 "38aeec7cdd035081d3a4c306394b19d677623bf76fa0913f6695127c7753aefd"
  end

  resource "parsimonious" do
    url "https://files.pythonhosted.org/packages/02/fc/067a3f89869a41009e1a7cdfb14725f8ddd246f30f63c645e8ef8a1c56f4/parsimonious-0.8.1.tar.gz"
    sha256 "3add338892d580e0cb3b1a39e4a1b427ff9f687858fdd61097053742391a9f6b"
  end

  resource "protobuf" do
    url "https://files.pythonhosted.org/packages/cd/02/0425c38def9047d77166abdc9bb66dcff2882095c57b952511c85720f03c/protobuf-3.9.0.tar.gz"
    sha256 "b3452bbda12b1cbe2187d416779de07b2ab4c497d83a050e43c344778763721d"
  end

  resource "py-ecc" do
    url "https://files.pythonhosted.org/packages/91/95/bd629558cb2f5dc934343ce8e9fd8403f8c0097ef59f324da0afe9ca888f/py_ecc-1.7.1.tar.gz"
    sha256 "67136ea75c35f7610b8060861c9999eecbe7f22c690882daadbe4e1712a314c0"
  end

  resource "py-evm" do
    url "https://files.pythonhosted.org/packages/d9/01/22f63f8edb79b3b0f0308ac6d5ea7a4f3e699276649bed6c8b5df0539d97/py-evm-0.2.0a42.tar.gz"
    sha256 "fffc877923baa1fb2ea8925b14a36b96c6cfd2bc3f121387d5f9e98f4ef4178e"
  end

  resource "py-geth" do
    url "https://files.pythonhosted.org/packages/31/6c/5f6a3ab4f5078b8c1474190be5575564d0b1f20d0a6fc7fc473dfd14be34/py-geth-2.1.0.tar.gz"
    sha256 "ab9ed996e1282dcb128e6749bb9db20f3139ae68894fbc5ecb9a7a56a5f0bc3e"
  end

  resource "pycparser" do
    url "https://files.pythonhosted.org/packages/68/9e/49196946aee219aead1290e00d1e7fdeab8567783e83e1b9ab5585e6206a/pycparser-2.19.tar.gz"
    sha256 "a988718abfad80b6b157acce7bf130a30876d27603738ac39f140993246b25b3"
  end

  resource "pycryptodome" do
    url "https://files.pythonhosted.org/packages/e2/7b/12f76a8bd427ebc54f24a0df6fd776fda48087d6a9a32ae0dbc3341dac3f/pycryptodome-3.8.2.tar.gz"
    sha256 "5bc40f8aa7ba8ca7f833ad2477b9d84e1bfd2630b22a46d9bbd221982f8c3ac0"
  end

  resource "pyethash" do
    url "https://files.pythonhosted.org/packages/6c/40/5bb02ad7e2fae9b04cd0c391dda81213bc786c30c8381b018600cfc7ce62/pyethash-0.1.27.tar.gz"
    sha256 "ff66319ce26b9d77df1f610942634dac9742e216f2c27b051c0a2c2dec9c2818"
  end

  resource "pypandoc" do
    url "https://files.pythonhosted.org/packages/71/81/00184643e5a10a456b4118fc12c96780823adb8ed974eb2289f29703b29b/pypandoc-1.4.tar.gz"
    sha256 "e914e6d5f84a76764887e4d909b09d63308725f0cbb5293872c2c92f07c11a5b"
  end

  resource "pysha3" do
    url "https://files.pythonhosted.org/packages/73/bf/978d424ac6c9076d73b8fdc8ab8ad46f98af0c34669d736b1d83c758afee/pysha3-1.0.2.tar.gz"
    sha256 "fe988e73f2ce6d947220624f04d467faf05f1bbdbc64b0a201296bb3af92739e"
  end

  resource "requests" do
    url "https://files.pythonhosted.org/packages/01/62/ddcf76d1d19885e8579acb1b1df26a852b03472c0e46d2b959a714c90608/requests-2.22.0.tar.gz"
    sha256 "11e007a8a2aa0323f5a921e9e6a2d7e4e67d9877e85773fba9ba6419025cbeb4"
  end

  resource "rlp" do
    url "https://files.pythonhosted.org/packages/9e/ea/beac98688ce787b80608c26b532ec9e2dd72876f0a97bcfddb68911f8673/rlp-1.1.0.tar.gz"
    sha256 "ebe80a03c50e3d6aac47f44ddd45048bb99e411203cd764f5da1330e6d83821c"
  end

  resource "semantic_version" do
    url "https://files.pythonhosted.org/packages/72/83/f76958017f3094b072d8e3a72d25c3ed65f754cc607fdb6a7b33d84ab1d5/semantic_version-2.6.0.tar.gz"
    sha256 "2a4328680073e9b243667b201119772aefc5fc63ae32398d6afafff07c4f54c0"
  end

  resource "six" do
    url "https://files.pythonhosted.org/packages/dd/bf/4138e7bfb757de47d1f4b6994648ec67a51efe58fa907c1e11e350cddfca/six-1.12.0.tar.gz"
    sha256 "d16a0141ec1a18405cd4ce8b4613101da75da0e9a7aec5bdd4fa804d0e0eba73"
  end

  resource "toolz" do
    url "https://files.pythonhosted.org/packages/22/8e/037b9ba5c6a5739ef0dcde60578c64d49f45f64c5e5e886531bfbc39157f/toolz-0.10.0.tar.gz"
    sha256 "08fdd5ef7c96480ad11c12d472de21acd32359996f69a5259299b540feba4560"
  end

  resource "trie" do
    url "https://files.pythonhosted.org/packages/30/0c/1010330d772c8f9d1ac43a9ebfac1f9ab15e59b82f4cdc231d06bd605be7/trie-1.4.0.tar.gz"
    sha256 "5c9501bc1af2c065502601370fc991c496c186c725ca408993d65a0792c2949b"
  end

  resource "urllib3" do
    url "https://files.pythonhosted.org/packages/4c/13/2386233f7ee40aa8444b47f7463338f3cbdf00c316627558784e3f542f07/urllib3-1.25.3.tar.gz"
    sha256 "dbe59173209418ae49d485b87d1681aefa36252ee85884c31346debd19463232"
  end

  resource "varint" do
    url "https://files.pythonhosted.org/packages/a8/fe/1ea0ba0896dfa47186692655b86db3214c4b7c9e0e76c7b1dc257d101ab1/varint-1.0.2.tar.gz"
    sha256 "a6ecc02377ac5ee9d65a6a8ad45c9ff1dac8ccee19400a5950fb51d594214ca5"
  end

  resource "web3" do
    url "https://files.pythonhosted.org/packages/a0/3c/ac15afa6cdd4246dcf07b689cae6ec1a4d4a6026e135d381398a80f2e4d8/web3-5.0.0.tar.gz"
    sha256 "e57b7e7f63d0643bb5f2bae8b2f53cff45ae2f0dff4f886d773dba988224191f"
  end

  resource "websockets" do
    url "https://files.pythonhosted.org/packages/ba/60/59844a5cef2428cb752bd4f446b72095b1edee404a58c27e87cd12a141e2/websockets-7.0.tar.gz"
    sha256 "08e3c3e0535befa4f0c4443824496c03ecc25062debbcf895874f8a0b4c97c9f"
  end

  def install
    virtualenv_create(libexec, "python3")
    virtualenv_install_with_resources
  end

  test do	
    # `test do` will create, run in and delete a temporary directory.	
    #	
    # This test will fail and we won't accept that! For Homebrew/homebrew-core	
    # this will need to be a test that verifies the functionality of the	
    # software. Run the test with `brew test ethpm-cli`. Options passed	
    # to `brew install` such as `--HEAD` also need to be provided to `brew test`.	
    #	
    # The installed folder is not in the path, so use the entire path to any	
    # executables being tested: `system "#{bin}/program", "do", "something"`.	
    system "false"	
  end
end
