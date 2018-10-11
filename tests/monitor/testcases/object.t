# first the setup
I add table ip t
O -

I add counter ip t c
O add counter ip t c { packets 0 bytes 0 }

I delete counter ip t c
O -

I add quota ip t q 25 mbytes
O add quota ip t q { 25 mbytes }

I delete quota ip t q
O -

I add limit ip t l rate 1/second
O add limit ip t l { rate 1/second }

I delete limit ip t l
O -

I add ct helper ip t cth { type "sip" protocol tcp; l3proto ip; }
O -

I delete ct helper ip t cth
O -

I add ct timeout ip t ctt { protocol udp; l3proto ip; policy = { unreplied: 15, replied: 12 }; }
O -

I delete ct timeout ip t ctt
O -
