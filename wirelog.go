// Copyright 2025 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fuse

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"syscall"
	"time"

	"github.com/jacobsa/fuse/fuseops"
)

// Fields that are ignored
var ignoredFields = []string{"OpContext", "Callback", "Dst", "Data", "Crtime"}

// Fields that are always response fields
var responseFields = []string{"Entry", "Attributes", "AttributesExpiration", "BytesRead"}

// Copy fields from a *fuseop.SomeOp to a map.
func copyFields(op any, dst map[string]any, fields ...string) {
	includeFields := map[string]struct{}{}
	for _, field := range fields {
		includeFields[field] = struct{}{}
	}
	v := reflect.ValueOf(op).Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() == reflect.Ptr && f.IsNil() {
			continue
		}
		if f.Kind() == reflect.Func {
			continue
		}
		fieldName := t.Field(i).Name
		if len(includeFields) > 0 {
			if _, ok := includeFields[fieldName]; !ok {
				continue
			}
		} else if slices.Contains(ignoredFields, fieldName) {
			continue
		} else if slices.Contains(responseFields, fieldName) {
			continue
		}
		dst[fieldName] = f.Interface()
	}
}

// Format a wire log entry
func formatWirelogEntry(op any, opErr error, wlog WlogRecord) ([]byte, error) {
	v := reflect.ValueOf(op).Elem()
	t := v.Type()

	wlog["Operation"] = t.Name()
	wlog["Duration"] = time.Since(wlog["StartTime"].(time.Time)) / time.Microsecond

	// Result of the operation
	var errno syscall.Errno
	if opErr == nil {
		wlog["Status"] = 0
	} else if errors.As(opErr, &errno) {
		wlog["Status"] = int(errno)
	}

	// Separate section for the operation context
	if f := v.FieldByName("OpContext"); f.IsValid() {
		if ctx, ok := f.Interface().(fuseops.OpContext); ok {
			wlog["Context"] = ctx
		}
	}

	// Split out request and response parameters base on request type. Most
	// operations are handled by the default case, expect those that have
	// fields that can either be a request or response field.
	request := map[string]any{}
	response := map[string]any{}

	switch typed := op.(type) {
	case *initOp:
		copyFields(op, request, "Kernel", "Flags", "Flags2")
		copyFields(op, response, "OutFlags", "OutFlags2", "Library", "MaxReadahead",
			"MaxBackground", "MaxWrite", "MaxPages")

	case *fuseops.StatFSOp:
		// All fields are response fields
		copyFields(op, response)

	case *fuseops.CreateFileOp:
		copyFields(op, request, "Parent", "Name", "Mode")
		copyFields(op, response, "Entry", "Handle")

	case *fuseops.OpenDirOp:
		copyFields(op, request, "Inode")
		copyFields(op, response, "Handle", "CacheDir", "KeepCache")

	case *fuseops.OpenFileOp:
		copyFields(op, request, "Inode", "UseDirectIO", "OpenFlags")
		copyFields(op, response, "Handle", "KeepPageCache")

	case *fuseops.WriteFileOp:
		copyFields(op, request)
		request["DataSize"] = len(typed.Data)

	case *fuseops.ReadSymlinkOp:
		copyFields(op, request, "Inode")
		copyFields(op, response, "Target")

	default:
		copyFields(op, request)
		copyFields(op, response, responseFields...)
	}

	if len(request) > 0 {
		wlog["Request"] = request
	}
	if len(response) > 0 {
		wlog["Response"] = response
	}

	buf, err := json.MarshalIndent(wlog, "", "  ")
	if err == nil {
		buf = append(buf, '\n')
	}
	return buf, err
}
