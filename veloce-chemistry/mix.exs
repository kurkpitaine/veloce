defmodule Chemistry.MixProject do
  use Mix.Project

  def project do
    [
      app: :chemistry,
      version: "0.1.0",
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      compilers: [:asn1] ++ Mix.compilers(),
      asn1_paths: "../veloce-asn1/asn",
      asn1_options: [:maps, :uper]
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
      {:chumak, "~> 1.4"},
      {:asn1_compiler, "~> 0.1.1"}
    ]
  end
end
