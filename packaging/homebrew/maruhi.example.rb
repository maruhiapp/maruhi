# 生成物 — 手で編集しない。
# apps/cli/scripts/generate-formula.ts が Release の checksums.txt から作る
# (maruhiapp/maruhi)。更新手順は docs/RELEASING.md の「Homebrew tap の更新」。
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
    # アーカイブにはバイナリ 1 本しか入っていない。`mh` はインストーラ側で
    # 張る(ADR-0015 裁定 6/7)
    bin.install_symlink "maruhi" => "mh"
  end

  test do
    assert_equal version.to_s, shell_output("#{bin}/maruhi --version").strip
  end
end
