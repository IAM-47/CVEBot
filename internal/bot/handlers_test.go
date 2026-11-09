package bot

import (
	"CVEBot/internal/storage"
	"errors"
	"reflect"
	"testing"
)

func ptr[T any](v T) *T { return &v }
func Test_parseSubscription(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    storage.Subscription
		wantErr bool
	}{
		{
			name: "both here",
			text: "nginx 1.24.0",
			want: storage.Subscription{Product: "nginx", Version: ptr("1.24.0"), MinSeverity: 1, Kev: false},
		},
		{
			name: "no version",
			text: "openssl",
			want: storage.Subscription{Product: "openssl", MinSeverity: 1, Kev: false},
		},
		{
			name: "caps",
			text: "NGINX 1.24.0",
			want: storage.Subscription{Product: "nginx", Version: ptr("1.24.0"), MinSeverity: 1, Kev: false},
		},
		{
			name: "extra spaces",
			text: "    nginx     1.24.0",
			want: storage.Subscription{Product: "nginx", Version: ptr("1.24.0"), MinSeverity: 1, Kev: false},
		},
		{
			name: "3 words product",
			text: "apache http server",
			want: storage.Subscription{Product: "apache http server", MinSeverity: 1, Kev: false},
		},
		{
			name: "3 words product + caps + spaces",
			text: "Apache    HTTP    server 2.4",
			want: storage.Subscription{Product: "apache http server", Version: ptr("2.4"), MinSeverity: 1, Kev: false},
		},
		{
			name:    "empty",
			text:    "",
			want:    storage.Subscription{},
			wantErr: true,
		},
		{
			name: "with severity",
			text: "nginx 1.24.0 high",
			want: storage.Subscription{Product: "nginx", Version: ptr("1.24.0"), MinSeverity: 3, Kev: false},
		},
		{
			name:    "with only spaces",
			text:    "  ",
			want:    storage.Subscription{},
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

func Test_subscribeReply(t *testing.T) {
	type args struct {
		oldSev *int
		oldKev *bool
		sub    storage.Subscription
	}
	tests := []struct {
		name    string
		args    args
		wantMsg string
	}{
		{
			name: "new subscription",
			args: args{sub: storage.Subscription{
				Product:     "nginx",
				Version:     ptr("1.24.0"),
				MinSeverity: 3,
				Kev:         false,
			}},
			wantMsg: SuccessfulSubscription,
		},
		{
			name: "nothing changed",
			args: args{ptr(3), ptr(false), storage.Subscription{
				Product:     "nginx",
				Version:     ptr("1.24.0"),
				MinSeverity: 3,
				Kev:         false,
			}},
			wantMsg: AlreadySubscribed,
		},
		{
			name: "severity changed",
			args: args{ptr(3), ptr(false), storage.Subscription{
				Product:     "nginx",
				Version:     ptr("1.24.0"),
				MinSeverity: 4,
				Kev:         false,
			}},
			wantMsg: "Updated HIGH to CRITICAL",
		},
		{
			name: "kev turned on",
			args: args{ptr(3), ptr(false), storage.Subscription{
				Product:     "nginx",
				Version:     ptr("1.24.0"),
				MinSeverity: 3,
				Kev:         true,
			}},
			wantMsg: "Updated KEV",
		},
		{
			name: "kev turned off",
			args: args{ptr(3), ptr(true), storage.Subscription{
				Product:     "nginx",
				Version:     ptr("1.24.0"),
				MinSeverity: 3,
				Kev:         false,
			}},
			wantMsg: "Updated KEV",
		},
		{
			name: "both changed",
			args: args{ptr(3), ptr(false), storage.Subscription{
				Product:     "nginx",
				Version:     ptr("1.24.0"),
				MinSeverity: 4,
				Kev:         true,
			}},
			wantMsg: "Updated HIGH to CRITICAL\nUpdated KEV",
		},
		{
			name: "severity lowered",
			args: args{ptr(3), ptr(false), storage.Subscription{
				Product:     "nginx",
				Version:     ptr("1.24.0"),
				MinSeverity: 1,
				Kev:         true,
			}},
			wantMsg: "Updated HIGH to LOW\nUpdated KEV",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotMsg := subscribeReply(tt.args.oldSev, tt.args.oldKev, tt.args.sub); gotMsg != tt.wantMsg {
				t.Errorf("subscribeReply() = %v, want %v", gotMsg, tt.wantMsg)
			}
		})
	}
}
