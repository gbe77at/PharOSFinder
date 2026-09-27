#!/bin/bash
# Construit « Pharos Finder.app » (universelle arm64 + x86_64) et PharosFinder.dmg.
# Prérequis : Command Line Tools (xcode-select --install). Aucun compte développeur requis.
set -euo pipefail
cd "$(dirname "$0")"

NAME="Pharos Finder"
BUNDLE_ID="fr.guillaume.pharosfinder"
VERSION="1.0"
MIN_OS="13.0"
BUILD="build"
APP="$BUILD/$NAME.app"
DMG="$BUILD/PharosFinder.dmg"

say() { printf "\n\033[1;34m▸ %s\033[0m\n" "$1"; }
die() { printf "\n\033[1;31m✗ %s\033[0m\n" "$1"; exit 1; }

command -v swiftc >/dev/null || die "swiftc introuvable : lance « xcode-select --install » puis relance ce script."

say "Nettoyage"
# Un ancien moteur lancé en root a pu laisser des fichiers root dans le bundle : on écarte le
# dossier (renommer ne demande pas de droits) au lieu d'échouer. À supprimer : sudo rm -rf .build-old-*
rm -rf "$BUILD" 2>/dev/null || { mv "$BUILD" ".build-old-$(date +%s)" && echo "  ⚠︎ ancien build écarté (fichiers root)"; }
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

say "Compilation SwiftUI"
BINS=()
for ARCH in arm64 x86_64; do
  OUT="$BUILD/PharosFinder-$ARCH"
  if swiftc -O -swift-version 5 -parse-as-library \
       -target "$ARCH-apple-macos$MIN_OS" \
       Sources/*.swift -o "$OUT"; then
    BINS+=("$OUT")
    echo "  ✓ $ARCH"
  elif [ "$ARCH" = "x86_64" ]; then
    echo "  ⚠︎ x86_64 ignoré (compilation impossible) — app arm64 uniquement"
  else
    die "La compilation a échoué (voir les erreurs ci-dessus)."
  fi
done
lipo -create "${BINS[@]}" -output "$APP/Contents/MacOS/PharosFinder"

say "Ressources"
cp Resources/pharos_finder.py Resources/finder_vendors.py Resources/oui.txt.gz "$APP/Contents/Resources/"
iconutil -c icns Resources/AppIcon.iconset -o "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$NAME</string>
  <key>CFBundleDisplayName</key><string>$NAME</string>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleExecutable</key><string>PharosFinder</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleDevelopmentRegion</key><string>fr</string>
  <key>LSMinimumSystemVersion</key><string>$MIN_OS</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSSupportsAutomaticTermination</key><false/>
  <key>NSAppleEventsUsageDescription</key>
  <string>Pharos Finder ouvre une session SSH dans Terminal vers l'équipement choisi.</string>
  <key>NSLocalNetworkUsageDescription</key>
  <string>Pharos Finder recherche les équipements TP-Link PharOS sur ton réseau local.</string>
  <key>NSAppTransportSecurity</key>
  <dict><key>NSAllowsLocalNetworking</key><true/></dict>
</dict>
</plist>
PLIST

say "Signature ad hoc"
codesign --force --deep --sign - "$APP"
codesign --verify --deep "$APP" && echo "  ✓ signature valide"

say "Image disque"
STAGE="$BUILD/dmg"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$NAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE" "$BUILD"/PharosFinder-*

say "Terminé"
echo "  App : $(pwd)/$APP"
echo "  DMG : $(pwd)/$DMG"
[ "${1:-}" = "--open" ] && open "$DMG"
exit 0
