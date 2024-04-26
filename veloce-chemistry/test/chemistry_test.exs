defmodule ChemistryTest do
  use ExUnit.Case
  doctest Chemistry

  test "greets the world" do
    assert Chemistry.hello() == :world
  end
end
