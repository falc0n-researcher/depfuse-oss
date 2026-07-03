package verdict_test

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/verdict"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestVerdictFixNowProdT1(t *testing.T) {
	comp := models.Component{Name: "express", Version: "4.17.1", Scope: models.ScopeProd}
	v, _ := verdict.Compute(comp, models.PriorityP1, models.ConfidenceHigh)
	require.Equal(t, models.VerdictFixNow, v)
}

func TestVerdictFixDevT1(t *testing.T) {
	comp := models.Component{Name: "eslint", Scope: models.ScopeDev}
	v, _ := verdict.Compute(comp, models.PriorityP1, models.ConfidenceHigh)
	require.Equal(t, models.VerdictFixSoon, v)
}

func TestLowConfidenceAppendsCaveat(t *testing.T) {
	comp := models.Component{Name: "express", Version: "4.17.1", Scope: models.ScopeProd}
	v, reason := verdict.Compute(comp, models.PriorityP1, models.ConfidenceLow)
	require.Equal(t, models.VerdictFixNow, v)
	require.Contains(t, reason, "low confidence")
}

func TestComputeAdvisoryNeverShipsKEV(t *testing.T) {
	v, _ := verdict.ComputeAdvisory(models.PriorityP0, models.ConfidenceHigh)
	require.Equal(t, models.VerdictPatchNow, v)
	v, _ = verdict.ComputeAdvisory(models.PriorityP1, models.ConfidenceHigh)
	require.Equal(t, models.VerdictPatchNow, v)
	v, _ = verdict.ComputeAdvisory(models.PriorityP2, models.ConfidenceHigh)
	require.Equal(t, models.VerdictPatchSoon, v)
	v, _ = verdict.ComputeAdvisory(models.PriorityP3, models.ConfidenceHigh)
	require.Equal(t, models.VerdictWatch, v)
	v, _ = verdict.ComputeAdvisory(models.PriorityP4, models.ConfidenceHigh)
	require.Equal(t, models.VerdictWatch, v)
}

func TestCIFailProdOnly(t *testing.T) {
	fail := verdict.ParseFailTiers("T0,T1")
	require.True(t, verdict.ShouldFailCI(models.Component{Scope: models.ScopeProd}, models.PriorityP1, fail))
	require.False(t, verdict.ShouldFailCI(models.Component{Scope: models.ScopeDev}, models.PriorityP1, fail))
}
