defmodule Chemistry.MixProject do
  use Mix.Project

  def project do
    compilers = case System.get_env("COMPILE_PROTO") do
      "1" ->
         [:asn1, :proto]
      _ ->
        Mix.shell().info("Skipping ASN.1 and Protobuf compilation")
        []
    end

    [
      app: :chemistry,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      compilers: compilers ++ Mix.compilers(),
      asn1_paths: "../veloce-asn1/asn/messages",
      asn1_options: [:uper, :jer, :verbose],
      protoc_opts: [
        paths: ["../veloce-ipc/schema"],
        dest: "lib/proto",
        package_prefix: "Proto",
        gen_descriptors: true,
        include_docs: true
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :asn1],
      mod: {Chemistry, []}
    ]
  end

  defp deps do
    [
      {:protobuf, "~> 0.12.0"},
      {:protobuf_compiler,
       git: "https://github.com/OffgridElectric/protobuf_compiler.git", runtime: false},
      {:chumak, "~> 1.4"},
      {:asn1_compiler, "~> 0.1.1", runtime: false},
      {:amqp, "~> 3.3"}
    ]
  end
end
