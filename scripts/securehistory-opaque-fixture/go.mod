module securehistoryopaquefixture

go 1.26.0

require go.mau.fi/mautrix-meta v0.0.0

replace go.mau.fi/mautrix-meta => /meta

// mautrix-meta's own replace; a dependency's replaces do not apply, so it is repeated here.
replace github.com/imroc/req/v3 => github.com/beeper/req/v3 v3.0.0-20260925135712-b49593750e56
