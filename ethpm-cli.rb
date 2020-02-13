class EthpmCli < Formula
    include Language::Python::Virtualenv

  desc "CLI tool for ethPM ecosystem."
  homepage "https://github.com/ethereum/ethpm-cli"
  url "https://files.pythonhosted.org/packages/3e/bc/2db0a2891305e9171166f7660d9cfebf91e4e99a7c372a24f69205e5da9c/ethpm-cli-0.2.0.tar.gz"
  sha256 "949e40ed4e3e997bc2ac78705968fdf15fe6af9dda3cadac08e0ab3a967bfd50"

  depends_on "python3"
  depends_on "pandoc" => :build

  resource "appnope" do
    url "https://files.pythonhosted.org/packages/26/34/0f3a5efac31f27fabce64645f8c609de9d925fe2915304d1a40f544cff0e/appnope-0.1.0.tar.gz"
    sha256 "8b995ffe925347a2138d7ac0fe77155e4311a0ea6d6da4f5128fe4b3cbe5ed71"
  end

  resource "attrdict" do
    url "https://files.pythonhosted.org/packages/3f/72/614aae677d28e81a5bf830fadcf580803876ef76e0306902d3ca5790cd9a/attrdict-2.0.1.tar.gz"
    sha256 "35c90698b55c683946091177177a9e9c0713a0860f0e049febd72649ccd77b70"
  end

  resource "attrs" do
    url "https://files.pythonhosted.org/packages/98/c3/2c227e66b5e896e15ccdae2e00bbc69aa46e9a8ce8869cc5fa96310bf612/attrs-19.3.0.tar.gz"
    sha256 "f7b7ce16570fe9965acd6d30101a28f62fb4a7f9e926b3bbc9b61f8b04247e72"
  end

  resource "backcall" do
    url "https://files.pythonhosted.org/packages/84/71/c8ca4f5bb1e08401b916c68003acf0a0655df935d74d93bf3f3364b310e0/backcall-0.1.0.tar.gz"
    sha256 "38ecd85be2c1e78f77fd91700c76e14667dc21e2713b63876c0eb901196e01e4"
  end

  resource "base58" do
    url "https://files.pythonhosted.org/packages/40/bf/7f8109973337e67f038187ae93a97f2d55309402102ff88699f36c711fd5/base58-2.0.0.tar.gz"
    sha256 "c83584a8b917dc52dd634307137f2ad2721a9efb4f1de32fc7eaaaf87844177e"
  end

  resource "cached-property" do
    url "https://files.pythonhosted.org/packages/57/8e/0698e10350a57d46b3bcfe8eff1d4181642fd1724073336079cb13c5cf7f/cached-property-1.5.1.tar.gz"
    sha256 "9217a59f14a5682da7c4b8829deadbfc194ac22e9908ccf7c8820234e80a1504"
  end

  resource "certifi" do
    url "https://files.pythonhosted.org/packages/41/bf/9d214a5af07debc6acf7f3f257265618f1db242a3f8e49a9b516f24523a6/certifi-2019.11.28.tar.gz"
    sha256 "25b64c7da4cd7479594d035c08c2d809eb4aab3a26e5a990ea98cc450c320f1f"
  end

  resource "chardet" do
    url "https://files.pythonhosted.org/packages/fc/bb/a5768c230f9ddb03acc9ef3f0d4a3cf93462473795d18e9535498c8f929d/chardet-3.0.4.tar.gz"
    sha256 "84ab92ed1c4d4f16916e05906b6b75a6c0fb5db821cc65e70cbd64a3e2a5eaae"
  end

  resource "cytoolz" do
    url "https://files.pythonhosted.org/packages/62/b1/7f16703fe4a497879b1b457adf1e472fad2d4f030477698b16d2febf38bb/cytoolz-0.10.1.tar.gz"
    sha256 "82f5bba81d73a5a6b06f2a3553ff9003d865952fcb32e1df192378dd944d8a5c"
  end

  resource "decorator" do
    url "https://files.pythonhosted.org/packages/dc/c3/9d378af09f5737cfd524b844cd2fbb0d2263a35c11d712043daab290144d/decorator-4.4.1.tar.gz"
    sha256 "54c38050039232e1db4ad7375cfce6748d7b41c29e95a081c8a6d2c30364a2ce"
  end

  resource "eth-abi" do
    url "https://files.pythonhosted.org/packages/70/b9/8e3ad3228b7be63a48bca3229e01a4a00534aee4fd992292eef13699ee62/eth-abi-2.1.0.tar.gz"
    sha256 "a8f3cc48a057dfcc77d4138920d482a9b0d3044e0ad68f0bc1bd8762720e0c13"
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
    url "https://files.pythonhosted.org/packages/d5/44/e19b91a755bf911416240a598aec59212b9102408873011b51600ec346e0/eth-tester-0.2.0b2.tar.gz"
    sha256 "03554e01eec57faefba256cca8c88beab1651eefb39f2ca9a21493acccc056e2"
  end

  resource "eth-typing" do
    url "https://files.pythonhosted.org/packages/66/ee/a2a0972fbc18cb17c3bcfe3a3b8da3acad68f58d2292605a7c3c74286ac7/eth-typing-2.2.1.tar.gz"
    sha256 "cf9e5e9fb62cfeb1027823328569315166851c65c5774604d801b6b926ff65bc"
  end

  resource "eth-utils" do
    url "https://files.pythonhosted.org/packages/6c/a5/43752cf1c7f10a648ad344c9aeddb624885d6d39890b2c529a1707134818/eth-utils-1.8.4.tar.gz"
    sha256 "f398c649859cda5ef7c4ee2753468038d93be7d864de7631c06c3e73a7060649"
  end

  resource "hexbytes" do
    url "https://files.pythonhosted.org/packages/6c/96/c76cd573e7c3e38af32aa3e4ee9d9103efe33847b72f0507ac6d7a824307/hexbytes-0.2.0.tar.gz"
    sha256 "9e8b3e3dc4a7de23c0cf1bb3c3edfcc1f0df4b78927bad63816c27a027b8b7d1"
  end

  resource "idna" do
    url "https://files.pythonhosted.org/packages/ad/13/eb56951b6f7950cadb579ca166e448ba77f9d24efc03edd7e55fa57d04b7/idna-2.8.tar.gz"
    sha256 "c357b3f628cf53ae2c4c05627ecc484553142ca23264e593d327bcde5e9c3407"
  end

  resource "importlib-metadata" do
    url "https://files.pythonhosted.org/packages/0d/e4/638f3bde506b86f62235c595073066e7b8472fc9ee2b8c6491347f31d726/importlib_metadata-1.5.0.tar.gz"
    sha256 "06f5b3a99029c7134207dd882428a66992a9de2bef7c2b699b5641f9886c3302"
  end

  resource "ipfshttpclient" do
    url "https://files.pythonhosted.org/packages/bd/76/ec048dfcdf182d04cb1e7a1a1d23018fccc4c8eb6cca5a43c4edbc39262d/ipfshttpclient-0.4.12.tar.gz"
    sha256 "0a199a1005fe44bff9da28b5af4785b0b09ca700baac9d1e26718fe23fe89bb7"
  end

  resource "ipython" do
    url "https://files.pythonhosted.org/packages/ce/e1/b9234b258086f80f8507afb80f6774c6daf3bd9b2765190ee8e3cd2c4759/ipython-7.12.0.tar.gz"
    sha256 "d9459e7237e2e5858738ff9c3e26504b79899b58a6d49e574d352493d80684c6"
  end

  resource "ipython_genutils" do
    url "https://files.pythonhosted.org/packages/e8/69/fbeffffc05236398ebfcfb512b6d2511c622871dca1746361006da310399/ipython_genutils-0.2.0.tar.gz"
    sha256 "eb2e116e75ecef9d4d228fdc66af54269afa26ab4463042e33785b887c628ba8"
  end

  resource "jedi" do
    url "https://files.pythonhosted.org/packages/5a/b7/d7bdce4e0ae654125404b397b293ec8a0060a55c9e860794538701b19653/jedi-0.16.0.tar.gz"
    sha256 "d5c871cb9360b414f981e7072c52c33258d598305280fef91c6cae34739d65d5"
  end

  resource "jsonschema" do
    url "https://files.pythonhosted.org/packages/69/11/a69e2a3c01b324a77d3a7c0570faa372e8448b666300c4117a516f8b1212/jsonschema-3.2.0.tar.gz"
    sha256 "c8a85b28d377cc7737e46e2d9f2b4f44ee3c0e1deac6bf46ddefc7187d30797a"
  end

  resource "lru-dict" do
    url "https://files.pythonhosted.org/packages/00/a5/32ed6e10246cd341ca8cc205acea5d208e4053f48a4dced2b1b31d45ba3f/lru-dict-1.1.6.tar.gz"
    sha256 "365457660e3d05b76f1aba3e0f7fedbfcd6528e97c5115a351ddd0db488354cc"
  end

  resource "multiaddr" do
    url "https://files.pythonhosted.org/packages/12/f4/fa5353022ad8e0fd364bfa8b474f9562c36ce1305fad31fe52b849e30795/multiaddr-0.0.9.tar.gz"
    sha256 "30b2695189edc3d5b90f1c303abb8f02d963a3a4edf2e7178b975eb417ab0ecf"
  end

  resource "mypy-extensions" do
    url "https://files.pythonhosted.org/packages/63/60/0582ce2eaced55f65a4406fc97beba256de4b7a95a0034c6576458c6519f/mypy_extensions-0.4.3.tar.gz"
    sha256 "2d82818f5bb3e369420cb3c4060a7970edba416647068eb4c5343488a6c604a8"
  end

  resource "netaddr" do
    url "https://files.pythonhosted.org/packages/0c/13/7cbb180b52201c07c796243eeff4c256b053656da5cfe3916c3f5b57b3a0/netaddr-0.7.19.tar.gz"
    sha256 "38aeec7cdd035081d3a4c306394b19d677623bf76fa0913f6695127c7753aefd"
  end

  resource "parsimonious" do
    url "https://files.pythonhosted.org/packages/02/fc/067a3f89869a41009e1a7cdfb14725f8ddd246f30f63c645e8ef8a1c56f4/parsimonious-0.8.1.tar.gz"
    sha256 "3add338892d580e0cb3b1a39e4a1b427ff9f687858fdd61097053742391a9f6b"
  end

  resource "parso" do
    url "https://files.pythonhosted.org/packages/db/f4/f714d71a23b65d0be451131137152764e01e5f74607678cb8318a20d564a/parso-0.6.1.tar.gz"
    sha256 "56b2105a80e9c4df49de85e125feb6be69f49920e121406f15e7acde6c9dfc57"
  end

  resource "pexpect" do
    url "https://files.pythonhosted.org/packages/e5/9b/ff402e0e930e70467a7178abb7c128709a30dfb22d8777c043e501bc1b10/pexpect-4.8.0.tar.gz"
    sha256 "fc65a43959d153d0114afe13997d439c22823a27cefceb5ff35c2178c6784c0c"
  end

  resource "pickleshare" do
    url "https://files.pythonhosted.org/packages/d8/b6/df3c1c9b616e9c0edbc4fbab6ddd09df9535849c64ba51fcb6531c32d4d8/pickleshare-0.7.5.tar.gz"
    sha256 "87683d47965c1da65cdacaf31c8441d12b8044cdec9aca500cd78fc2c683afca"
  end

  resource "prompt-toolkit" do
    url "https://files.pythonhosted.org/packages/8f/bc/58ba47a2a864d8e3d968d03b577c85fbdf52c8d324a030df71ac9c06c1b5/prompt_toolkit-3.0.3.tar.gz"
    sha256 "a402e9bf468b63314e37460b68ba68243d55b2f8c4d0192f85a019af3945050e"
  end

  resource "protobuf" do
    url "https://files.pythonhosted.org/packages/c9/d5/e6e789e50e478463a84bd1cdb45aa408d49a2e1aaffc45da43d10722c007/protobuf-3.11.3.tar.gz"
    sha256 "c77c974d1dadf246d789f6dad1c24426137c9091e930dbf50e0a29c1fcf00b1f"
  end

  resource "ptyprocess" do
    url "https://files.pythonhosted.org/packages/7d/2d/e4b8733cf79b7309d84c9081a4ab558c89d8c89da5961bf4ddb050ca1ce0/ptyprocess-0.6.0.tar.gz"
    sha256 "923f299cc5ad920c68f2bc0bc98b75b9f838b93b599941a6b63ddbc2476394c0"
  end

  resource "py-ecc" do
    url "https://files.pythonhosted.org/packages/91/95/bd629558cb2f5dc934343ce8e9fd8403f8c0097ef59f324da0afe9ca888f/py_ecc-1.7.1.tar.gz"
    sha256 "67136ea75c35f7610b8060861c9999eecbe7f22c690882daadbe4e1712a314c0"
  end

  resource "py-evm" do
    url "https://files.pythonhosted.org/packages/75/7f/dcb2efdd5f9bbb0cb26e52adf0211c2ac9c01b68fe38eb4335fafe5b311d/py-evm-0.3.0a1.tar.gz"
    sha256 "3e1f39a74bbee0403ddddc28170950c576060f8d3b9a19e5ebf4980f2717d4b6"
  end

  resource "py-geth" do
    url "https://files.pythonhosted.org/packages/3e/0d/37c15e6227846f4bfa839446219c923852ee6b1857277b1f16267fc350e2/py-geth-2.2.0.tar.gz"
    sha256 "4af3d8e07738b2991d755c31d5de2d39231aa43c3ca28b74f44d7a5e9792eaff"
  end

  resource "pycryptodome" do
    url "https://files.pythonhosted.org/packages/37/84/5bb86e0a4cda99669ccf0814942889499dc11e3124fd4cc2f4faa447e966/pycryptodome-3.9.6.tar.gz"
    sha256 "bc22ced26ebc46546798fa0141f4418f1db116dec517f0aeaecec87cf7b2416c"
  end

  resource "pyethash" do
    url "https://files.pythonhosted.org/packages/6c/40/5bb02ad7e2fae9b04cd0c391dda81213bc786c30c8381b018600cfc7ce62/pyethash-0.1.27.tar.gz"
    sha256 "ff66319ce26b9d77df1f610942634dac9742e216f2c27b051c0a2c2dec9c2818"
  end

  resource "Pygments" do
    url "https://files.pythonhosted.org/packages/cb/9f/27d4844ac5bf158a33900dbad7985951e2910397998e85712da03ce125f0/Pygments-2.5.2.tar.gz"
    sha256 "98c8aa5a9f778fcd1026a17361ddaf7330d1b7c62ae97c3bb0ae73e0b9b6b0fe"
  end

  resource "pypandoc" do
    url "https://files.pythonhosted.org/packages/71/81/00184643e5a10a456b4118fc12c96780823adb8ed974eb2289f29703b29b/pypandoc-1.4.tar.gz"
    sha256 "e914e6d5f84a76764887e4d909b09d63308725f0cbb5293872c2c92f07c11a5b"
  end

  resource "pyrsistent" do
    url "https://files.pythonhosted.org/packages/90/aa/cdcf7ef88cc0f831b6f14c8c57318824c9de9913fe8de38e46a98c069a35/pyrsistent-0.15.7.tar.gz"
    sha256 "cdc7b5e3ed77bed61270a47d35434a30617b9becdf2478af76ad2c6ade307280"
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
    url "https://files.pythonhosted.org/packages/4d/8f/ae650dbc78d874f8728ea74e569e3513dd49931d56e1f4273c5f3fd0075a/rlp-1.2.0.tar.gz"
    sha256 "27273fc2dbc3513c1e05ea6b8af28aac8745fb09c164e39e2ed2807bf7e1b342"
  end

  resource "semantic-version" do
    url "https://files.pythonhosted.org/packages/67/24/7e8fcb6aa88bfc018f8e4c48c4dbc8e87d8c7b3c0d0d8b3b0c61a34d32c7/semantic_version-2.8.4.tar.gz"
    sha256 "352459f640f3db86551d8054d1288608b29a96e880c7746f0a59c92879d412a3"
  end

  resource "six" do
    url "https://files.pythonhosted.org/packages/21/9f/b251f7f8a76dec1d6651be194dfba8fb8d7781d10ab3987190de8391d08e/six-1.14.0.tar.gz"
    sha256 "236bdbdce46e6e6a3d61a337c0f8b763ca1e8717c03b369e87a7ec7ce1319c0a"
  end

  resource "termcolor" do
    url "https://files.pythonhosted.org/packages/8a/48/a76be51647d0eb9f10e2a4511bf3ffb8cc1e6b14e9e4fab46173aa79f981/termcolor-1.1.0.tar.gz"
    sha256 "1d6d69ce66211143803fbc56652b41d73b4a400a2891d7bf7a1cdf4c02de613b"
  end

  resource "toolz" do
    url "https://files.pythonhosted.org/packages/22/8e/037b9ba5c6a5739ef0dcde60578c64d49f45f64c5e5e886531bfbc39157f/toolz-0.10.0.tar.gz"
    sha256 "08fdd5ef7c96480ad11c12d472de21acd32359996f69a5259299b540feba4560"
  end

  resource "traitlets" do
    url "https://files.pythonhosted.org/packages/75/b0/43deb021bc943f18f07cbe3dac1d681626a48997b7ffa1e7fb14ef922b21/traitlets-4.3.3.tar.gz"
    sha256 "d023ee369ddd2763310e4c3eae1ff649689440d4ae59d7485eb4cfbbe3e359f7"
  end

  resource "trie" do
    url "https://files.pythonhosted.org/packages/30/0c/1010330d772c8f9d1ac43a9ebfac1f9ab15e59b82f4cdc231d06bd605be7/trie-1.4.0.tar.gz"
    sha256 "5c9501bc1af2c065502601370fc991c496c186c725ca408993d65a0792c2949b"
  end

  resource "typing-extensions" do
    url "https://files.pythonhosted.org/packages/e7/dd/f1713bc6638cc3a6a23735eff6ee09393b44b96176d3296693ada272a80b/typing_extensions-3.7.4.1.tar.gz"
    sha256 "091ecc894d5e908ac75209f10d5b4f118fbdb2eb1ede6a63544054bb1edb41f2"
  end

  resource "urllib3" do
    url "https://files.pythonhosted.org/packages/09/06/3bc5b100fe7e878d3dee8f807a4febff1a40c213d2783e3246edde1f3419/urllib3-1.25.8.tar.gz"
    sha256 "87716c2d2a7121198ebcb7ce7cccf6ce5e9ba539041cfbaeecfb641dc0bf6acc"
  end

  resource "varint" do
    url "https://files.pythonhosted.org/packages/a8/fe/1ea0ba0896dfa47186692655b86db3214c4b7c9e0e76c7b1dc257d101ab1/varint-1.0.2.tar.gz"
    sha256 "a6ecc02377ac5ee9d65a6a8ad45c9ff1dac8ccee19400a5950fb51d594214ca5"
  end

  resource "wcwidth" do
    url "https://files.pythonhosted.org/packages/5e/33/92333eb80be0c96385dee338f30b53e24a8b415d5785e225d789b3f90feb/wcwidth-0.1.8.tar.gz"
    sha256 "f28b3e8a6483e5d49e7f8949ac1a78314e740333ae305b4ba5defd3e74fb37a8"
  end

  resource "web3" do
    url "https://files.pythonhosted.org/packages/97/b9/c101a127d55f5911c5244428e19c1ada3e36a84baba872341bcb090c7a34/web3-5.5.1.tar.gz"
    sha256 "8def170567698f09f6ad1460f6a2dfba4a454b7ee30060c3f1ee7ed0273b91b8"
  end

  resource "websockets" do
    url "https://files.pythonhosted.org/packages/e9/2b/cf738670bb96eb25cb2caf5294e38a9dc3891a6bcd8e3a51770dbc517c65/websockets-8.1.tar.gz"
    sha256 "5c65d2da8c6bce0fca2528f69f44b2f977e06954c8512a952222cea50dad430f"
  end

  resource "wheel" do
    url "https://files.pythonhosted.org/packages/75/28/521c6dc7fef23a68368efefdcd682f5b3d1d58c2b90b06dc1d0b805b51ae/wheel-0.34.2.tar.gz"
    sha256 "8788e9155fe14f54164c1b9eb0a319d98ef02c160725587ad60f14ddc57b6f96"
  end

  resource "zipp" do
    url "https://files.pythonhosted.org/packages/11/b5/89f3ab6d45b2709863761bab58c574b2344ef215749abb5407818c21c9ca/zipp-2.1.0.tar.gz"
    sha256 "feae2f18633c32fc71f2de629bfb3bd3c9325cd4419642b1f1da42ee488d9b98"
  end

  def install
    virtualenv_create(libexec, "python3")
	# https://github.com/takluyver/flit/issues/245
	system libexec/"bin/pip", "install", "-v", "--no-deps", "--ignore-installed", "https://files.pythonhosted.org/packages/bd/76/ec048dfcdf182d04cb1e7a1a1d23018fccc4c8eb6cca5a43c4edbc39262d/ipfshttpclient-0.4.12.tar.gz#sha256=0a199a1005fe44bff9da28b5af4785b0b09ca700baac9d1e26718fe23fe89bb7"
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
