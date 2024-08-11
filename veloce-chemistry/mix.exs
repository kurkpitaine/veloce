defmodule Chemistry.MixProject do
  use Mix.Project

  def project do
    [
      app: :chemistry,
      version: "0.1.0",
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      compilers: [:asn1, :proto] ++ Mix.compilers(),
      asn1_paths: "../veloce-asn1/asn/messages",
      asn1_options: [:uper, :verbose],
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
      {:asn1_compiler, "~> 0.1.1", runtime: false}
    ]
  end
end
