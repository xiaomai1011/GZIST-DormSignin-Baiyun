package browserhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// The independent budget keeps restoration bounded even when the task was
// canceled. If the CDP transport already closed, restoration fails and abort
// proves process exit instead of returning a dirty browser to the next task.
func taskLeaseFinisher(pageCtx context.Context, cleanup func(context.Context) error, closeSession, release, abort func() error) func() error {
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(pageCtx), 3*time.Second)
			cleanErr := cleanup(cleanCtx)
			// A late successful return does not prove restoration within budget.
			cleanErr = errors.Join(cleanErr, cleanCtx.Err())
			cancel()
			closeErr := closeSession()
			result = errors.Join(cleanErr, closeErr)
			if result != nil {
				result = errors.Join(result, abort())
				return
			}
			if err := release(); err != nil {
				result = errors.Join(err, abort())
			}
		})
		return result
	}
}

func (c *Client) releaseTask(id uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	body, _ := json.Marshal(releaseRequest{ID: id})
	resp, err := c.do(ctx, http.MethodPost, "/release", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("task lease release: %s", resp.Status)
	}
	return nil
}
