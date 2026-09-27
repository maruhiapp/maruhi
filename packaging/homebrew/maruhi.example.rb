# Generated file — do not edit by hand.
# Built by apps/cli/scripts/generate-formula.ts from the Release's checksums.txt
# (maruhiapp/maruhi). Update procedure: docs/RELEASING.md, "Updating the Homebrew tap".
class Maruhi < Formula
  desc "Diskless, end-to-end encrypted secrets manager on Cloudflare"
  homepage "https://github.com/maruhiapp/maruhi"
  version "1.2.3"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/maruhiapp/maruhi/releases/download/v1.2.3/maruhi-darwin-arm64.tar.gz"
      sha256 "4444444444444444444444444444444444444444444444444444444444444444"
    end
    on_intel do
      url "https://github.com/maruhiapp/maruhi/releases/download/v1.2.3/maruhi-darwin-x64.tar.gz"
      sha256 "3333333333333333333333333333333333333333333333333333333333333333"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/maruhiapp/maruhi/releases/download/v1.2.3/maruhi-linux-arm64.tar.gz"
      sha256 "2222222222222222222222222222222222222222222222222222222222222222"
    end
    on_intel do
      url "https://github.com/maruhiapp/maruhi/releases/download/v1.2.3/maruhi-linux-x64.tar.gz"
      sha256 "1111111111111111111111111111111111111111111111111111111111111111"
    end
  end

  def install
    bin.install "maruhi"
    # The archive contains a single binary. `mh` is linked by the
    # installer side (ADR-0015 rulings 6/7)
    bin.install_symlink "maruhi" => "mh"
  end

  test do
    assert_equal version.to_s, shell_output("#{bin}/maruhi --version").strip
  end
end
