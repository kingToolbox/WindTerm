#!/usr/bin/env bash
#
# Build the WindTerm SDK and wrap it in a macOS .pkg installer.
#
# What this produces is the open source part of WindTerm - libraries and
# headers - not WindTerm.app. The application's source is not in this
# repository, so it cannot be built here.
#
# Usage:
#   scripts/build-pkg.sh [--arch arm64|x86_64|universal2]
#                        [--build-type Release|Debug]
#                        [--version X.Y.Z]
#                        [--output DIR]
#                        [--prefix /usr/local/windterm]
#                        [--jobs N]
#
# Signing is off by default. Set PKG_SIGN_IDENTITY to a "Developer ID
# Installer: ..." identity to sign the resulting package.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ARCH="arm64"
BUILD_TYPE="Release"
VERSION=""
OUTPUT_DIR="${REPO_ROOT}/dist"
INSTALL_PREFIX="/usr/local/windterm"
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"
IDENTIFIER="dev.oronui.windterm.sdk"

while [[ $# -gt 0 ]]; do
	case "$1" in
		--arch)       ARCH="$2"; shift 2 ;;
		--build-type) BUILD_TYPE="$2"; shift 2 ;;
		--version)    VERSION="$2"; shift 2 ;;
		--output)     OUTPUT_DIR="$2"; shift 2 ;;
		--prefix)     INSTALL_PREFIX="$2"; shift 2 ;;
		--jobs)       JOBS="$2"; shift 2 ;;
		-h|--help)    sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
		*) echo "error: unknown argument '$1'" >&2; exit 2 ;;
	esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
	echo "error: this script builds a macOS installer and must run on macOS." >&2
	exit 1
fi

case "${ARCH}" in
	arm64)      CMAKE_ARCHS="arm64" ;;
	x86_64)     CMAKE_ARCHS="x86_64" ;;
	universal2)
		CMAKE_ARCHS="arm64;x86_64"
		echo "note: universal2 needs every dependency to be universal too."
		echo "      Homebrew's Qt and OpenSSL are single-architecture, so this"
		echo "      only links against a universal Qt (the official Qt installer"
		echo "      ships one) or with -DWINDTERM_WITH_QT=OFF."
		;;
	*) echo "error: --arch must be arm64, x86_64 or universal2 (got '${ARCH}')" >&2; exit 2 ;;
esac

for tool in cmake pkgbuild productbuild lipo; do
	command -v "${tool}" >/dev/null 2>&1 || { echo "error: '${tool}' not found in PATH." >&2; exit 1; }
done

if [[ -z "${VERSION}" ]]; then
	VERSION="$(sed -n 's/.*VERSION \([0-9][0-9.]*\)$/\1/p' "${REPO_ROOT}/CMakeLists.txt" | head -1)"
	[[ -n "${VERSION}" ]] || VERSION="0.0.0"
fi

BUILD_DIR="${REPO_ROOT}/build/${ARCH}"
STAGE_DIR="${REPO_ROOT}/build/stage-${ARCH}"
WORK_DIR="${REPO_ROOT}/build/pkg-${ARCH}"
PKG_NAME="WindTerm-SDK-${VERSION}-macOS-${ARCH}.pkg"

echo "==> WindTerm SDK ${VERSION} | arch=${ARCH} | ${BUILD_TYPE}"

rm -rf "${STAGE_DIR}" "${WORK_DIR}"
mkdir -p "${WORK_DIR}/component" "${WORK_DIR}/resources" "${OUTPUT_DIR}"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

echo "==> Configuring"
cmake -S "${REPO_ROOT}" -B "${BUILD_DIR}" \
	-DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
	-DCMAKE_OSX_ARCHITECTURES="${CMAKE_ARCHS}" \
	-DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
	${CMAKE_PREFIX_PATH:+-DCMAKE_PREFIX_PATH="${CMAKE_PREFIX_PATH}"} \
	${WINDTERM_CMAKE_EXTRA_ARGS:-}

echo "==> Building"
cmake --build "${BUILD_DIR}" --parallel "${JOBS}"

echo "==> Staging into ${STAGE_DIR}${INSTALL_PREFIX}"
DESTDIR="${STAGE_DIR}" cmake --install "${BUILD_DIR}"

# ---------------------------------------------------------------------------
# Verify the payload really is the architecture we asked for
# ---------------------------------------------------------------------------

# Drop leftover Finder metadata and quarantine flags before packaging.
#
# This does not remove com.apple.provenance, which macOS stamps on every file
# and refuses to let anyone delete - pkgbuild prints "write: Permission denied"
# for it and then encodes it as an AppleDouble "._" entry inside the payload.
# That is the normal way extended attributes travel in a .pkg: the installer
# merges them back onto the real files and no "._" file is ever written to
# disk. Nothing to fix there.
echo "==> Cleaning extended attributes from the payload"
xattr -cr "${STAGE_DIR}" 2>/dev/null || true
find "${STAGE_DIR}" \( -name '._*' -o -name '.DS_Store' \) -delete

echo "==> Verifying architectures"
found_any=0
while IFS= read -r binary; do
	found_any=1
	info="$(lipo -info "${binary}")"
	for want in ${CMAKE_ARCHS//;/ }; do
		if [[ "${info}" != *"${want}"* ]]; then
			echo "error: ${binary} is missing ${want}" >&2
			echo "       ${info}" >&2
			exit 1
		fi
	done
	echo "    ok  $(basename "${binary}"): ${info#*: }"
done < <(find "${STAGE_DIR}" \( -name '*.a' -o -name '*.dylib' \) -type f)

if [[ "${found_any}" -eq 0 ]]; then
	echo "error: no libraries were staged - nothing to package." >&2
	exit 1
fi

# ---------------------------------------------------------------------------
# Package
# ---------------------------------------------------------------------------

echo "==> pkgbuild"
PKGBUILD_ARGS=(
	--root "${STAGE_DIR}"
	--identifier "${IDENTIFIER}"
	--version "${VERSION}"
	--install-location "/"
)
if [[ -n "${PKG_SIGN_IDENTITY:-}" ]]; then
	PKGBUILD_ARGS+=(--sign "${PKG_SIGN_IDENTITY}")
fi
pkgbuild "${PKGBUILD_ARGS[@]}" "${WORK_DIR}/component/windterm-sdk-component.pkg"

cp "${REPO_ROOT}/packaging/macos/welcome.html" "${WORK_DIR}/resources/welcome.html"
cp "${REPO_ROOT}/src/LICENSE" "${WORK_DIR}/resources/LICENSE.txt"

echo "==> productbuild"
PRODUCTBUILD_ARGS=(
	--distribution "${REPO_ROOT}/packaging/macos/distribution.xml"
	--package-path "${WORK_DIR}/component"
	--resources "${WORK_DIR}/resources"
)
if [[ -n "${PKG_SIGN_IDENTITY:-}" ]]; then
	PRODUCTBUILD_ARGS+=(--sign "${PKG_SIGN_IDENTITY}")
fi
productbuild "${PRODUCTBUILD_ARGS[@]}" "${OUTPUT_DIR}/${PKG_NAME}"

echo "==> Checking the package is installable"
installer -pkg "${OUTPUT_DIR}/${PKG_NAME}" -pkginfo >/dev/null

echo
echo "Package: ${OUTPUT_DIR}/${PKG_NAME}"
shasum -a 256 "${OUTPUT_DIR}/${PKG_NAME}"
