defmodule Bonfire.OpenID.Provider.CIMDBodyCapTest do
  @moduledoc """
  A client metadata document over the size limit is refused whatever its content type: one served as JSON (which `Req` decodes before we see it) is held to the same limit as one served as text. A small document is accepted either way.

  `Req` is given a stub in place of the network through its global default options, so this module does not run alongside others.
  """
  use ExUnit.Case, async: false

  @moduletag :backend

  alias Bonfire.OpenID.Provider.CIMD

  @url "https://client.example.com/oauth/metadata"

  setup do
    previous = Req.default_options()
    Req.default_options(plug: {Req.Test, __MODULE__})
    on_exit(fn -> Req.default_options(previous) end)
    :ok
  end

  defp doc(extra \\ %{}),
    do:
      Map.merge(
        %{
          "client_id" => @url,
          "client_name" => "My App",
          "redirect_uris" => ["https://client.example.com/callback"]
        },
        extra
      )

  # a document well over the limit
  defp oversized, do: doc(%{"client_name" => String.duplicate("a", 20_000)})

  test "a small document served as JSON is accepted (control)" do
    Req.Test.stub(__MODULE__, &Req.Test.json(&1, doc()))

    assert {:ok, %{client_id: @url, name: "My App"}} = CIMD.fetch(@url)
  end

  test "a small document served as text is accepted (control)" do
    Req.Test.stub(__MODULE__, &Req.Test.text(&1, Jason.encode!(doc())))

    assert {:ok, %{client_id: @url}} = CIMD.fetch(@url)
  end

  test "an oversized document served as text is refused (control)" do
    Req.Test.stub(__MODULE__, &Req.Test.text(&1, Jason.encode!(oversized())))

    assert {:error, msg} = CIMD.fetch(@url)
    assert msg =~ "exceeds maximum allowed size"
  end

  test "an oversized document served as JSON is refused" do
    Req.Test.stub(__MODULE__, &Req.Test.json(&1, oversized()))

    assert {:error, msg} = CIMD.fetch(@url)
    assert msg =~ "exceeds maximum allowed size"
  end
end
