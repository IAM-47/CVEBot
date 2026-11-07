package main

import (
	"errors"
	"reflect"
	"testing"
)

func ptrString(s string) *string { return &s }
func Test_parseSubscription(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    Subscription
		wantErr bool
	}{
		{
			name: "both here",
			text: "nginx 1.24.0",
			want: Subscription{Product: "nginx", Version: ptrString("1.24.0")},
		},
		{
			name: "no version",
			text: "openssl",
			want: Subscription{Product: "openssl"},
		},
		{
			name: "caps",
			text: "NGINX 1.24.0",
			want: Subscription{Product: "nginx", Version: ptrString("1.24.0")},
		},
		{
			name: "extra spaces",
			text: "    nginx     1.24.0",
			want: Subscription{Product: "nginx", Version: ptrString("1.24.0")},
		},
		{
			name: "3 words product",
			text: "apache http server",
			want: Subscription{Product: "apache http server"},
		},
		{
			name: "3 words product + caps + spaces",
			text: "Apache    HTTP    server 2.4",
			want: Subscription{Product: "apache http server", Version: ptrString("2.4")},
		},
		{
			name:    "empty",
			text:    "",
			want:    Subscription{},
			wantErr: true,
		},
		{
			name: "with severity",
			text: "nginx 1.24.0 high",
			want: Subscription{Product: "nginx 1.24.0 high"},
		},
		{
			name:    "with only spaces",
			text:    "  ",
			want:    Subscription{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSubscription(tt.text)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, errBadFormat) {
				t.Errorf("error = %v, wantErr %v", err, errBadFormat)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got = %+v, want %+v", got, tt.want)
			}
		})
	}
}
