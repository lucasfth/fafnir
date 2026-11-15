# DRAFT, UNVERIFIED under Homebrew (only syntax-checked). Before use: copy into
# lucasfth/homebrew-tap/Formula/, tag v2026.0.0-beta.1, fill in sha256 with
#   curl -L https://github.com/lucasfth/fafnir/archive/refs/tags/v2026.0.0-beta.1.tar.gz | shasum -a 256
# then run `brew style`, `brew audit --strict --new` and `brew install --build-from-source`.
class Fafnir < Formula
  desc "Repository secrets with SOPS and age"
  homepage "https://github.com/lucasfth/fafnir"
  url "https://github.com/lucasfth/fafnir/archive/refs/tags/v2026.0.0-beta.1.tar.gz"
  sha256 "REPLACE_AFTER_TAGGING"
  license "Apache-2.0"
  head "https://github.com/lucasfth/fafnir.git", branch: "main"

  depends_on "go" => :build

  def install
    # macOS keychain support needs CGO; Homebrew's Go build env provides the SDK.
    ENV["CGO_ENABLED"] = "1"
    ldflags = "-X github.com/lucasfth/fafnir/internal/cli.Version=#{version}"
    system "go", "build", *std_go_args(ldflags:), "./cmd/fafnir"
  end

  test do
    assert_equal version.to_s, shell_output("#{bin}/fafnir version").strip
  end
end
