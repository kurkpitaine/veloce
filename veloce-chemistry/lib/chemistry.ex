defmodule Chemistry do
  alias Event.Event

  def start(_type, _args) do
    {:ok, sock} = :chumak.socket(:sub)

    topic = <<>>
    :chumak.subscribe(sock, topic)

    case :chumak.connect(sock, :tcp, ~c"localhost", 45556) do
      {:ok, _BindPid} ->
        IO.puts("Binding OK with Pid: #{inspect(sock)}")

      {:error, reason} ->
        IO.puts("Connection Failed for this reason: #{inspect(reason)}")
    end

    loop(sock)
  end

  def loop(socket) do
    {:ok, data} = :chumak.recv(socket)
    # IO.puts("Received: #{inspect(data)}")

    %Event{timestamp: _tst, event_type: evt} = Event.decode(data)

    case evt do
      {:cam_tx, uper} ->
        cam = :"CAM-PDU-Descriptions".decode(:CAM, uper)
        IO.puts("#{inspect(cam)}")
    end

    loop(socket)
  end
end
