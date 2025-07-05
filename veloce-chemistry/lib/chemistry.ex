require Logger

defmodule Chemistry do
  @moduledoc false

  use Application

  alias Chemistry.Subscriber
  alias Chemistry.Carotte

  def start(_type, _args) do
    Logger.configure(level: :debug)
    Application.ensure_started(:amqp)

    children = [
      Carotte.child_spec(host: "localhost", port: 5672, username: "guest", password: "guest"),
      Subscriber.child_spec(host: "localhost", port: 45556)
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Chemistry.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
