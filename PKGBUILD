pkgname=warpper
pkgver=0.1.0
pkgrel=1
pkgdesc="Warpper DNS filter"
arch=('any')
url="https://github.com/AllenRogers6/warpper"
license=('AGPL')
depends=(
  'python'
  'python-dnslib'
  'python-psutil'
  'python-cryptography'
  'nftables'
)
makedepends=(
  'python-build'
  'python-installer'
  'python-setuptools'
  'python-wheel'
)
checkdepends=(
  'python-pytest'
  'python-pytest-asyncio'
)
backup=('etc/warpper/warpper.conf')

source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
  cd "$srcdir/$pkgname-$pkgver"
  python -m build --wheel --no-isolation
}

check() {
  cd "$srcdir/$pkgname-$pkgver"
  python -m pytest tests/ -v
}

package() {
  cd "$srcdir/$pkgname-$pkgver"

  python -m installer --destdir="$pkgdir" dist/*.whl

  install -Dm640 config/warpper.conf \
    "$pkgdir/etc/warpper/warpper.conf"

  install -Dm644 systemd/warpperd.service \
    "$pkgdir/usr/lib/systemd/system/warpperd.service"
  install -Dm644 systemd/warpperd-update.service \
    "$pkgdir/usr/lib/systemd/system/warpperd-update.service"
  install -Dm644 systemd/warpperd-update.timer \
    "$pkgdir/usr/lib/systemd/system/warpperd-update.timer"

  install -Dm644 LICENSE \
    "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
