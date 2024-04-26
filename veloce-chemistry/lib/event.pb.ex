defmodule Event.Event do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"

  oneof :event_type, 0

  field :timestamp, 1, type: :uint64
  field :cam_rx, 10, type: :bytes, json_name: "camRx", oneof: 0
  field :cam_tx, 11, type: :bytes, json_name: "camTx", oneof: 0
  field :denm_rx, 12, type: :bytes, json_name: "denmRx", oneof: 0
  field :denm_tx, 13, type: :bytes, json_name: "denmTx", oneof: 0
  field :denm_dispatch, 100, type: Event.DenmDispatch, json_name: "denmDispatch", oneof: 0
  field :denm_process, 101, type: Event.DenmProcess, json_name: "denmProcess", oneof: 0
  field :denm_trigger_req, 102, type: Event.DenmTriggerReq, json_name: "denmTriggerReq", oneof: 0
end

defmodule Event.DenmDispatch do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"
end

defmodule Event.DenmProcess do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"
end

defmodule Event.DenmTriggerReq do
  @moduledoc false

  use Protobuf, syntax: :proto3, protoc_gen_elixir_version: "0.12.0"
end