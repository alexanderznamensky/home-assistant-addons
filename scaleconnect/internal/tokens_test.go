package internal

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReplaceKey(t *testing.T) {
	key := replaceKey("zepp/xiaomi:alex@gmail.com")
	require.Equal(t, "zepp/xiaomi:alex@gmail.com", key)

	key = replaceKey("xiaomi:alex@gmail.com")
	require.Equal(t, "xiaomi:alex@gmail.com", key)

	key = replaceKey("mifitness:alex@gmail.com")
	require.Equal(t, "xiaomi:alex@gmail.com", key)

	key = replaceKey("xiaomihome:alex@gmail.com")
	require.Equal(t, "xiaomi:alex@gmail.com", key)
}
