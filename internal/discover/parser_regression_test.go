package discover

import (
 "os"
 "path/filepath"
 "reflect"
 "testing"
)

func writeAuditFile(t *testing.T, root, rel, body string) {
 t.Helper()
 path := filepath.Join(root, rel)
 if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { t.Fatal(err) }
 if err := os.WriteFile(path, []byte(body), 0644); err != nil { t.Fatal(err) }
}

func TestNPMRegistryAliases(t *testing.T) {
 t.Parallel()
 for _, test := range []struct{name, body string}{
 {"v3", `{"packages":{"node_modules/alias":{"name":"real","version":"1.2.3"},"packages/local":{"name":"local","version":"1.0.0"},"node_modules/local":{"link":true,"resolved":"packages/local"}}}`},
 {"v1", `{"dependencies":{"alias":{"version":"npm:real@1.2.3"}}}`},
 {"v1-scoped", `{"dependencies":{"alias":{"version":"npm:@scope/real@1.2.3"}}}`},
 } {
 t.Run(test.name, func(t *testing.T){
 root := t.TempDir()
 writeAuditFile(t, root, "package-lock.json", test.body)
 inv := Walk(Options{Roots: []string{root}})
 var got []string
 for _, p := range inv.AllPackages(){ got = append(got, p.String()) }
 want := []string{"real@1.2.3"}
 if test.name == "v1-scoped" {want = []string{"@scope/real@1.2.3"}}
 if !reflect.DeepEqual(got, want) || len(inv.Errors)>0 {t.Fatalf("packages %v errors %v; want %v",got,inv.Errors,want)}
 })
 }
}

func TestExplicitSymlinkRoot(t *testing.T) {
 t.Parallel()
 root := t.TempDir()
 target := filepath.Join(root, "actual")
 writeAuditFile(t, target, "requirements.txt", "requests==2.31.0\n")
 link := filepath.Join(root, "linked")
 if err := os.Symlink(target, link); err != nil {t.Fatal(err)}
 inv := Walk(Options{Roots: []string{link, target}})
 if got := inv.AllPackages(); len(got)!=1 || len(inv.Sources)!=1 {t.Fatalf("packages %v sources %v",got,inv.Sources)}
 inv = Walk(Options{Roots: []string{link}})
 if got := inv.AllPackages(); len(got)!=1 {t.Fatalf("symlink root packages %v",got)}
}

func TestExplicitRootBeyondEarlierDepthLimit(t *testing.T) {
 t.Parallel()
 root := t.TempDir()
 writeAuditFile(t, root, "a/b/requirements.txt", "requests==2.31.0\n")
 inv := Walk(Options{Roots: []string{root, filepath.Join(root,"a","b")}, MaxDepth:1})
 if got := inv.AllPackages(); len(got)!=1 {t.Fatalf("explicit root skipped: %v errors %v",got,inv.Errors)}
}

func TestRequirementsOnlyExactPins(t *testing.T) {
 t.Parallel()
 root := t.TempDir()
 writeAuditFile(t, root, "requirements.txt", "wild==1.2.*\ncompatible==1.2.*,!=1.2.1\nexact==2.0 ; python_version > '3'\n")
 inv := Walk(Options{Roots: []string{root}})
 got := inv.AllPackages()
 if len(got)!=1 || got[0].String()!="exact@2.0" { t.Fatalf("packages: %v",got) }
}

func TestTOMLCommentsAndSubtables(t *testing.T) {
 t.Parallel()
 root := t.TempDir()
 writeAuditFile(t, root, "poetry.lock", "[[package]] # dependency\nname = 'Requests' # normalized\nversion = \"2.31.0\" # pin\n[package.source]\nname = 'mirror'\n[[package]]\nname = 'idna'\nversion = '3.6'\n")
 inv := Walk(Options{Roots: []string{root}})
 var got []string
 for _, p := range inv.AllPackages(){got=append(got,p.String())}
 if !reflect.DeepEqual(got, []string{"idna@3.6","requests@2.31.0"}) {t.Fatalf("packages %v",got)}
}
