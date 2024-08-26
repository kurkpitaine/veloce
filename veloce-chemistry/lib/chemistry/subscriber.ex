require Logger

defmodule Chemistry.Subscriber do
  use GenServer

  alias Proto.Event.Event

  def child_spec(host: host, port: port) do
    %{
      id: Chemistry.Subscriber,
      start: {Chemistry.Subscriber, :start_link, [host, port]}
    }
  end

  def start_link(host, port) do
    Logger.info("Starting Veloce IPC subscriber on #{host} port #{port}")
    GenServer.start_link(__MODULE__, {host, port}, name: __MODULE__)
  end

  # GenServer callbacks
  @impl true
  def init({host, port}) do
    {:ok, {host, port}, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, {host, port}) do
    connect(host, port)
    {:noreply, {host, port}}
  end

  defp connect(host, port) do
    Logger.info("Connecting to Veloce IPC producer")

    # connect to socket
    {:ok, socket} = :chumak.socket(:sub)
    Logger.info("Connected IPC socket on #{host} port #{port}")
    :chumak.subscribe(socket, <<>>)
    Logger.debug("Subscribed to IPC events")

    case :chumak.connect(socket, :tcp, String.to_charlist(host), port) do
      {:ok, pid} -> Logger.debug("Binding ok to IPC socket pid #{inspect(pid)}")
      {:error, reason} -> Logger.error("Binding IPC socket failed: #{reason}")
      _ -> Logger.info("???")
    end

    # start tx loop
    loop(socket)
  end

  defp loop(socket) do
    with {:ok, payload} <- :chumak.recv(socket) do
      Task.start(fn -> process(payload) end)
      loop(socket)
    else
      _ -> loop(socket)
    end
  end

  defp process(payload) do
      with %Event{timestamp: _tst, event_type: {:cam_tx, cam}} <- Event.decode(payload),
           {:ok, uper} <- :"CAM-PDU-Descriptions".decode(:CAM, cam),
           {:ok, jer } <- :"CAM-PDU-Descriptions".jer_encode(:CAM, uper) do
            Chemistry.Carotte.publish(jer)
      else
        %Event{} -> Logger.error("Unhandled event type")
        _ -> Logger.error("ASN.1 encode/decode error")
      end
  catch
      _ -> Logger.error("Failed to decode payload: #{inspect(payload)}")
  end
end
