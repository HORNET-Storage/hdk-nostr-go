package connmgr

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"reflect"
	"strings"
	"time"

	types "github.com/HORNET-Storage/go-hornet-storage-lib/lib"
	"github.com/fxamacker/cbor/v2"
)

// isTerminalError checks if an error represents a terminal condition that should not be retried
func isTerminalError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// These are normal stream closure conditions, not actual errors
	terminalConditions := []string{
		"stream reset",
		"stream closed",
		"Application error 0x0",
		"connection reset",
		"EOF",
		io.EOF.Error(),
	}

	for _, condition := range terminalConditions {
		if strings.Contains(errStr, condition) {
			return true
		}
	}

	// Also check if it's actually io.EOF
	if err == io.EOF {
		return true
	}

	return false
}

type ReadOption func(*readOptions)

type readOptions struct {
	timeout    time.Duration
	maxRetries int
	retryDelay time.Duration
}

func defaultReadOptions() *readOptions {
	return &readOptions{
		timeout:    300 * time.Second, // 5 minutes for large repository operations
		maxRetries: 3,
		retryDelay: 300 * time.Millisecond,
	}
}

func WithTimeout(timeout time.Duration) ReadOption {
	return func(o *readOptions) {
		o.timeout = timeout
	}
}

func WithRetries(maxRetries int) ReadOption {
	return func(o *readOptions) {
		o.maxRetries = maxRetries
	}
}

func WithRetryDelay(delay time.Duration) ReadOption {
	return func(o *readOptions) {
		o.retryDelay = delay
	}
}

type WriteOption func(*writeOptions)

type writeOptions struct {
	timeout    time.Duration
	maxRetries int
	retryDelay time.Duration
}

func defaultWriteOptions() *writeOptions {
	return &writeOptions{
		timeout:    300 * time.Second, // 5 minutes for large repository operations
		maxRetries: 3,
		retryDelay: 300 * time.Millisecond,
	}
}

func WithWriteTimeout(timeout time.Duration) WriteOption {
	return func(o *writeOptions) {
		o.timeout = timeout
	}
}

func WithWriteRetries(maxRetries int) WriteOption {
	return func(o *writeOptions) {
		o.maxRetries = maxRetries
	}
}

func WithWriteRetryDelay(delay time.Duration) WriteOption {
	return func(o *writeOptions) {
		o.retryDelay = delay
	}
}

func BuildErrorMessage(message string, err error) types.ErrorMessage {
	log.Println("\n====[STREAM ERROR MESSAGE]====")
	if len(message) > 0 {
		log.Println(message)
	}
	if err != nil {
		log.Println(err)
	}
	log.Println("")

	return types.ErrorMessage{
		Message: fmt.Sprintf(message, err),
	}
}

func BuildResponseMessage(response bool, message ...string) types.ResponseMessage {
	msg := ""
	if len(message) > 0 {
		msg = message[0]
	}
	return types.ResponseMessage{
		Ok:      response,
		Message: msg,
	}
}

func WriteErrorToStream(stream types.Stream, message string, err error) error {
	// Use quieter logging for terminal errors (expected during normal connection closure)
	if err != nil && isTerminalError(err) {
		log.Printf("[stream] Client disconnected: %s", message)
	} else if err != nil {
		log.Printf("[stream error] %s: %v", message, err)
	} else if len(message) > 0 {
		log.Printf("[stream error] %s", message)
	}

	// Build the error message string
	errMsg := message
	if err != nil && message != "" {
		errMsg = fmt.Sprintf("%s: %v", message, err)
	} else if err != nil {
		errMsg = err.Error()
	}

	errorPayload := types.ErrorMessage{
		Message: errMsg,
	}

	envelope := types.MessageEnvelope{
		Type:    "error",
		Payload: errorPayload,
	}

	enc := cbor.NewEncoder(stream)
	return enc.Encode(&envelope)
}

func WriteResponseToStream(stream types.Stream, response bool) error {
	return WriteMessageToStream(stream, BuildResponseMessage(response))
}

func WaitForResponse(stream types.Stream) (*types.ResponseMessage, error) {
	return ReadMessageFromStream[types.ResponseMessage](stream)
}

func WaitForUploadMessage(stream types.Stream) (*types.UploadMessage, error) {
	return ReadMessageFromStream[types.UploadMessage](stream)
}

func WaitForDownloadMessage(stream types.Stream) (*types.DownloadMessage, error) {
	return ReadMessageFromStream[types.DownloadMessage](stream)
}

func WaitForQueryMessage(stream types.Stream) (*types.QueryMessage, error) {
	return ReadMessageFromStream[types.QueryMessage](stream)
}

func WaitForAdvancedQueryMessage(stream types.Stream) (*types.AdvancedQueryMessage, error) {
	return ReadMessageFromStream[types.AdvancedQueryMessage](stream)
}

func ReadMessageFromStream[T any](stream types.Stream, options ...ReadOption) (*T, error) {
	// Parse options
	opts := defaultReadOptions()
	for _, option := range options {
		option(opts)
	}

	var lastErr error
	for attempt := 0; attempt <= opts.maxRetries; attempt++ {
		if attempt > 0 {
			// Only log retry if it's not a terminal error
			if !isTerminalError(lastErr) {
				log.Printf("Retrying read (attempt %d/%d) after error: %v",
					attempt, opts.maxRetries, lastErr)
			}

			time.Sleep(opts.retryDelay)
		}

		envelope, err := ReadEnvelopeFromStream(stream, opts.timeout)
		if err != nil {
			lastErr = err
			// Don't retry on terminal errors (stream closure, EOF, etc.)
			if isTerminalError(err) || opts.maxRetries == 0 || attempt == opts.maxRetries {
				return nil, err
			}
			continue
		}

		if envelope.Type == "error" {
			errorBytes, err := cbor.Marshal(envelope.Payload)
			if err != nil {
				lastErr = fmt.Errorf("failed to marshal error payload: %w", err)
				if isTerminalError(err) || opts.maxRetries == 0 || attempt == opts.maxRetries {
					return nil, lastErr
				}
				continue
			}

			var errorMsg types.ErrorMessage
			if err := cbor.Unmarshal(errorBytes, &errorMsg); err != nil {
				lastErr = fmt.Errorf("failed to unmarshal error payload: %w", err)
				if isTerminalError(err) || opts.maxRetries == 0 || attempt == opts.maxRetries {
					return nil, lastErr
				}
				continue
			}

			lastErr = fmt.Errorf("remote error: %s", errorMsg.Message)
			return nil, lastErr
		}

		payloadBytes, err := cbor.Marshal(envelope.Payload)
		if err != nil {
			lastErr = fmt.Errorf("failed to marshal payload: %w", err)
			if isTerminalError(err) || opts.maxRetries == 0 || attempt == opts.maxRetries {
				return nil, lastErr
			}
			continue
		}

		var message T
		if err := cbor.Unmarshal(payloadBytes, &message); err != nil {
			lastErr = fmt.Errorf("failed to unmarshal payload to %T: %w", message, err)
			if isTerminalError(err) || opts.maxRetries == 0 || attempt == opts.maxRetries {
				return nil, lastErr
			}
			continue // Retry
		}

		return &message, nil
	}

	return nil, lastErr
}

func ReadEnvelopeFromStream(stream types.Stream, timeoutDuration time.Duration) (*types.MessageEnvelope, error) {
	if timeoutDuration == 0 {
		timeoutDuration = 300 * time.Second // Default timeout increased for large repositories
	}

	// Create a channel to signal completion
	done := make(chan struct{})
	var envelope types.MessageEnvelope
	var decodeErr error

	// Start a goroutine to decode the message
	go func() {
		streamDecoder := cbor.NewDecoder(stream)
		decodeErr = streamDecoder.Decode(&envelope)
		close(done)
	}()

	// Wait for either completion or timeout
	select {
	case <-done:
		if decodeErr != nil {
			if decodeErr == io.EOF {
				return nil, io.EOF
			}
			return nil, fmt.Errorf("error decoding message: %w", decodeErr)
		}
		return &envelope, nil
	case <-time.After(timeoutDuration):
		// Close the stream to unblock the decode goroutine so it doesn't leak.
		// After a timeout the stream is unusable anyway.
		stream.Close()
		return nil, fmt.Errorf("read operation timed out after %v", timeoutDuration)
	}
}

func WriteMessageToStream[T any](stream types.Stream, message T, options ...WriteOption) error {
	// Parse options
	opts := defaultWriteOptions()
	for _, option := range options {
		option(opts)
	}

	typeName := reflect.TypeOf(message).String()

	envelope := types.MessageEnvelope{
		Type:    typeName,
		Payload: message,
	}

	var lastErr error
	for attempt := 0; attempt <= opts.maxRetries; attempt++ {
		if attempt > 0 {
			// Only log retry if it's not a terminal error
			if !isTerminalError(lastErr) {
				log.Printf("Retrying write (attempt %d/%d) after error: %v",
					attempt, opts.maxRetries, lastErr)
			}

			// Wait before retry if this isn't the first attempt
			time.Sleep(opts.retryDelay)
		}

		// Create a channel to signal completion
		done := make(chan struct{})
		var writeErr error

		// Start a goroutine to encode and write the message
		go func() {
			enc := cbor.NewEncoder(stream)
			writeErr = enc.Encode(&envelope)
			close(done)
		}()

		// Wait for either completion or timeout
		select {
		case <-done:
			if writeErr != nil {
				lastErr = writeErr
				// Don't retry on terminal errors (stream closure, etc.)
				if isTerminalError(writeErr) || opts.maxRetries == 0 || attempt == opts.maxRetries {
					return writeErr
				}
				continue // Retry
			}
			return nil // Success
		case <-time.After(opts.timeout):
			// Close the stream to unblock the encode goroutine so it doesn't leak.
			stream.Close()
			lastErr = fmt.Errorf("write operation timed out after %v", opts.timeout)
			if opts.maxRetries == 0 || attempt == opts.maxRetries {
				return lastErr
			}
			continue // Retry
		}
	}

	return lastErr
}

func ReadJsonMessageFromStream[T any](stream types.Stream) (*T, error) {
	streamDecoder := json.NewDecoder(stream)

	var message T

	timeout := time.NewTimer(300 * time.Second) // Increased timeout for large operations

wait:
	for {
		select {
		case <-timeout.C:
			return nil, fmt.Errorf("WaitForMessage timed out")
		default:
			err := streamDecoder.Decode(&message)

			if err != nil {
				return nil, err
			}

			if err == io.EOF {
				return nil, err
			}

			break wait
		}
	}

	return &message, nil
}

func WriteJsonMessageToStream[T any](stream types.Stream, message T) error {
	enc := json.NewEncoder(stream)

	if err := enc.Encode(&message); err != nil {
		return err
	}

	return nil
}
