defmodule Bonfire.OpenID.DanceCase do
  use ExUnit.CaseTemplate
  import Tesla.Mock
  import Untangle
  import Bonfire.UI.Common.Testing.Helpers
  alias Bonfire.Common.TestInstanceRepo

  setup_all tags do
    info("Start with a DanceTest")

    Bonfire.Common.Test.Interactive.setup_test_repo(tags)

    on_exit(fn ->
      info("Done with a DanceTest")
      # this callback needs to checkout its own connection since it
      # runs in its own process
      # :ok = Ecto.Adapters.SQL.Sandbox.checkout(repo())
      # Ecto.Adapters.SQL.Sandbox.mode(repo(), :auto)

      # Object.delete(actor1)
      # Object.delete(actor2)
      :ok
    end)

    TestInstanceRepo.apply(fn ->
      if !Bonfire.Boundaries.Circles.exists?(Bonfire.Boundaries.Circles.get_id!(:local)) do
        info("Seems boundary fixtures are missing on test instance, running now")
        Bonfire.Boundaries.Scaffold.insert()
      end
    end)

    [
      local: fake_user!("Local"),
      remote: TestInstanceRepo.apply(fn -> fake_user!("Remote") end)
    ]
  end
end

defmodule ReqCookieJar do
  use Agent

  def new() do
    Agent.start_link(fn -> "" end, name: __MODULE__)
  end

  defp get_cookie do
    Agent.get(__MODULE__, & &1)
  end

  defp set_cookie([]), do: nil

  defp set_cookie(val) do
    Agent.update(__MODULE__, fn _ -> val end)
  end

  def attach(%Req.Request{} = request) do
    request
    |> Req.Request.append_response_steps(
      cookie_jar: fn {req, res} ->
        Req.Response.get_header(res, "set-cookie")
        |> set_cookie()

        {req, res}
      end
    )
    |> Req.Request.append_request_steps(
      cookie_jar: &Req.Request.put_header(&1, "cookie", get_cookie())
    )
  end
end
