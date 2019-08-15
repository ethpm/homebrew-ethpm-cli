class EthpmCli < Formula
  include Language::Python::Virtualenv
  desc "CLI tool for ethPM ecosystem."
  homepage "www.ethpm.com"
  url "https://github.com/ethpm/ethpm-cli/blob/master/archives/ethpm-cli-0.1.0a3.tar.gz?raw=true"
  sha256 "f9f94c30f2cfc63a5ddce7a3aaa1dbd5ddbafc0f1cb21293aa07f8f647562353"
  depends_on "python@3"

  def install
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
