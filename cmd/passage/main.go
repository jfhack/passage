package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jfhack/passage/internal/auth"
	"github.com/jfhack/passage/internal/config"
	"github.com/jfhack/passage/internal/quickdocker"
	"github.com/jfhack/passage/internal/tunnel"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]
	var err error
	switch sub {
	case "server":
		err = runServer(args)
	case "client":
		err = runClient(args)
	case "verify":
		err = runVerify(args)
	case "keygen":
		err = runKeygen(args)
	case "pq-keygen":
		err = runPQKeygen(args)
	case "fingerprint":
		err = runFingerprint(args)
	case "quick-docker":
		err = runQuickDocker(args)
	case "version", "-v", "--version":
		fmt.Println(version)
		return
	case "help", "-h", "--help":
		usage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", sub)
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `passage %s — secure single-port reverse TCP tunnel

Usage:
  passage server       -config <file>
  passage client       -config <file>
  passage verify       -config <file>
  passage keygen       -out    <file> -pq-out <file>
  passage pq-keygen    -out    <file>
  passage fingerprint  <cert.pem>
  passage quick-docker [-out <dir>] [-force] <spec.yaml>
  passage version

Run 'passage <subcommand> -h' for the flags of any subcommand.
`, version)
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, nil))
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to server.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("server: -config is required")
	}
	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		return err
	}
	logger := newLogger().With("role", "server", "version", version)
	srv, err := tunnel.NewServer(cfg, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to client.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("client: -config is required")
	}
	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		return err
	}
	logger := newLogger().With("role", "client", "version", version, "client_id", cfg.Identity.ID)
	cli, err := tunnel.NewClient(cfg, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return cli.Run(ctx)
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to client.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("verify: -config is required")
	}
	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		return err
	}
	logger := newLogger().With("role", "verify", "client_id", cfg.Identity.ID)
	cli, err := tunnel.NewClient(cfg, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cli.VerifyOnce(ctx); err != nil {
		return err
	}
	fmt.Println("ok: reachability and authentication succeeded")
	return nil
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "path to write the Ed25519 private key")
	pqOut := fs.String("pq-out", "", "path to write the ML-DSA-65 private key (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("keygen: -out is required")
	}
	if *pqOut == "" {
		return fmt.Errorf("keygen: -pq-out is required (hybrid auth is mandatory)")
	}
	pub, priv, err := auth.GenerateKeypair()
	if err != nil {
		return err
	}
	if err := auth.WritePrivkeyPEM(*out, priv); err != nil {
		return err
	}
	fmt.Printf("wrote private key: %s\n", *out)
	fmt.Printf("public key (paste into server.yaml as pubkey):\n%s\n", auth.EncodePubkey(pub))
	pqPub, _, seed, err := auth.GeneratePQKeypair()
	if err != nil {
		return err
	}
	if err := auth.WritePQPrivkeyPEM(*pqOut, seed); err != nil {
		return err
	}
	fmt.Printf("wrote pq private key: %s\n", *pqOut)
	fmt.Printf("pq public key (paste into server.yaml as pq_pubkey):\n%s\n", auth.EncodePQPubkey(pqPub))
	return nil
}

func runPQKeygen(args []string) error {
	fs := flag.NewFlagSet("pq-keygen", flag.ContinueOnError)
	out := fs.String("out", "", "path to write the ML-DSA-65 private key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("pq-keygen: -out is required")
	}
	pub, _, seed, err := auth.GeneratePQKeypair()
	if err != nil {
		return err
	}
	if err := auth.WritePQPrivkeyPEM(*out, seed); err != nil {
		return err
	}
	fmt.Printf("wrote pq private key: %s\n", *out)
	fmt.Printf("pq public key (paste into server.yaml as pq_pubkey):\n%s\n", auth.EncodePQPubkey(pub))
	return nil
}

func runFingerprint(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("fingerprint: exactly one argument required (path to PEM cert)")
	}
	fp, err := tunnel.FingerprintFromCertFile(args[0])
	if err != nil {
		return err
	}
	fmt.Println(fp)
	return nil
}

func runQuickDocker(args []string) error {
	fs := flag.NewFlagSet("quick-docker", flag.ContinueOnError)
	out := fs.String("out", ".", "output directory (will contain server/ and client/ subdirs)")
	force := fs.Bool("force", false, "overwrite existing server/ and client/ output dirs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("quick-docker: exactly one argument required (path to spec)")
	}
	spec, err := quickdocker.Load(fs.Arg(0))
	if err != nil {
		return err
	}
	res, err := quickdocker.Generate(spec, quickdocker.GenerateOptions{OutDir: *out, Force: *force})
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", res.ServerDir)
	fmt.Printf("wrote %s\n", res.ClientDir)
	fmt.Printf("server fingerprint:    %s\n", res.Fingerprint)
	fmt.Printf("client public key:     %s\n", res.PubKey)
	if res.PQPubKey != "" {
		fmt.Printf("client pq public key:  %s\n", res.PQPubKey)
	}
	fmt.Printf("server compose project: %s\n", res.ServerProject)
	fmt.Printf("client compose project: %s\n", res.ClientProject)
	fmt.Println()
	fmt.Println("next steps:")
	fmt.Printf("  copy %s to the public-facing host, then: docker compose up -d\n", res.ServerDir)
	fmt.Printf("  copy %s to the private-network host, then: docker compose up -d\n", res.ClientDir)
	return nil
}
