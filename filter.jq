[.[] 
  | select(
      ._source.layers.icmpv6["icmpv6.type"] == "128" 
      or ._source.layers.icmpv6["icmpv6.type"] == "129"
    )
  | {
      type: (
        if ._source.layers.icmpv6["icmpv6.type"] == "128" then "ping request"
        elif ._source.layers.icmpv6["icmpv6.type"] == "129" then "ping reply"
        else "other"
        
        end
      ),
      sequence: (
        ._source.layers.icmpv6["icmpv6.echo.sequence_number"]? // "0" | tonumber
      ),
      nodes: (
        ._source.layers.ipv6["ipv6.hopopts"]?.["ipv6.opt"]?
        | select(."Pre-allocated Trace"? != null)
        | ."Pre-allocated Trace"."Trace Data"?
        // {}
      )
    }
]