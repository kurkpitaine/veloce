require Logger

defmodule Chemistry.Carotte do
  use GenServer

  def child_spec(host: host, port: port, username: username, password: password) do
    %{
      id: Chemistry.Carotte,
      start: {Chemistry.Carotte, :start_link, [host, port, username, password]}
    }
  end

  def start_link(host, port, username, password) do
    Logger.info("Starting Carotte AMQP client on #{host} port #{port}")
    GenServer.start_link(__MODULE__, {host, port, username, password}, name: __MODULE__)
  end

  def publish(element) do
    GenServer.cast(__MODULE__, {:publish, element})
  end

  # GenServer callbacks
  @impl true
  def init({host, port, username, password}) do
    Logger.info("Connecting to AMQP broker")

    {:ok, conn} = AMQP.Connection.open(host: host, port: port, username: username, password: password, heartbeat: 1)
    Logger.info("Connected to AMQP broker on #{host} port #{port}")
    {:ok, chan} = AMQP.Channel.open(conn)
    Logger.info("Opened channel")
    {:ok, chan}
  end

  @impl true
  def handle_cast({:publish, element}, chan) do
    with :ok <- AMQP.Basic.publish(chan, "amq.topic", "veloce.cam", element) do
        Logger.debug("Published element to AMQP broker")
    else
      _ -> Logger.error("Failed to open channel")
    end

    {:noreply, chan}
  end
end
