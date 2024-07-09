//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator. DO NOT EDIT.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package fake

import (
	"context"
	"errors"
	"fmt"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/fake/server"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v5"
	"net/http"
	"net/url"
	"regexp"
)

// HubVirtualNetworkConnectionsServer is a fake server for instances of the armnetwork.HubVirtualNetworkConnectionsClient type.
type HubVirtualNetworkConnectionsServer struct {
	// BeginCreateOrUpdate is the fake for method HubVirtualNetworkConnectionsClient.BeginCreateOrUpdate
	// HTTP status codes to indicate success: http.StatusOK, http.StatusCreated
	BeginCreateOrUpdate func(ctx context.Context, resourceGroupName string, virtualHubName string, connectionName string, hubVirtualNetworkConnectionParameters armnetwork.HubVirtualNetworkConnection, options *armnetwork.HubVirtualNetworkConnectionsClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armnetwork.HubVirtualNetworkConnectionsClientCreateOrUpdateResponse], errResp azfake.ErrorResponder)

	// BeginDelete is the fake for method HubVirtualNetworkConnectionsClient.BeginDelete
	// HTTP status codes to indicate success: http.StatusOK, http.StatusAccepted, http.StatusNoContent
	BeginDelete func(ctx context.Context, resourceGroupName string, virtualHubName string, connectionName string, options *armnetwork.HubVirtualNetworkConnectionsClientBeginDeleteOptions) (resp azfake.PollerResponder[armnetwork.HubVirtualNetworkConnectionsClientDeleteResponse], errResp azfake.ErrorResponder)

	// Get is the fake for method HubVirtualNetworkConnectionsClient.Get
	// HTTP status codes to indicate success: http.StatusOK
	Get func(ctx context.Context, resourceGroupName string, virtualHubName string, connectionName string, options *armnetwork.HubVirtualNetworkConnectionsClientGetOptions) (resp azfake.Responder[armnetwork.HubVirtualNetworkConnectionsClientGetResponse], errResp azfake.ErrorResponder)

	// NewListPager is the fake for method HubVirtualNetworkConnectionsClient.NewListPager
	// HTTP status codes to indicate success: http.StatusOK
	NewListPager func(resourceGroupName string, virtualHubName string, options *armnetwork.HubVirtualNetworkConnectionsClientListOptions) (resp azfake.PagerResponder[armnetwork.HubVirtualNetworkConnectionsClientListResponse])
}

// NewHubVirtualNetworkConnectionsServerTransport creates a new instance of HubVirtualNetworkConnectionsServerTransport with the provided implementation.
// The returned HubVirtualNetworkConnectionsServerTransport instance is connected to an instance of armnetwork.HubVirtualNetworkConnectionsClient via the
// azcore.ClientOptions.Transporter field in the client's constructor parameters.
func NewHubVirtualNetworkConnectionsServerTransport(srv *HubVirtualNetworkConnectionsServer) *HubVirtualNetworkConnectionsServerTransport {
	return &HubVirtualNetworkConnectionsServerTransport{
		srv:                 srv,
		beginCreateOrUpdate: newTracker[azfake.PollerResponder[armnetwork.HubVirtualNetworkConnectionsClientCreateOrUpdateResponse]](),
		beginDelete:         newTracker[azfake.PollerResponder[armnetwork.HubVirtualNetworkConnectionsClientDeleteResponse]](),
		newListPager:        newTracker[azfake.PagerResponder[armnetwork.HubVirtualNetworkConnectionsClientListResponse]](),
	}
}

// HubVirtualNetworkConnectionsServerTransport connects instances of armnetwork.HubVirtualNetworkConnectionsClient to instances of HubVirtualNetworkConnectionsServer.
// Don't use this type directly, use NewHubVirtualNetworkConnectionsServerTransport instead.
type HubVirtualNetworkConnectionsServerTransport struct {
	srv                 *HubVirtualNetworkConnectionsServer
	beginCreateOrUpdate *tracker[azfake.PollerResponder[armnetwork.HubVirtualNetworkConnectionsClientCreateOrUpdateResponse]]
	beginDelete         *tracker[azfake.PollerResponder[armnetwork.HubVirtualNetworkConnectionsClientDeleteResponse]]
	newListPager        *tracker[azfake.PagerResponder[armnetwork.HubVirtualNetworkConnectionsClientListResponse]]
}

// Do implements the policy.Transporter interface for HubVirtualNetworkConnectionsServerTransport.
func (h *HubVirtualNetworkConnectionsServerTransport) Do(req *http.Request) (*http.Response, error) {
	rawMethod := req.Context().Value(runtime.CtxAPINameKey{})
	method, ok := rawMethod.(string)
	if !ok {
		return nil, nonRetriableError{errors.New("unable to dispatch request, missing value for CtxAPINameKey")}
	}

	var resp *http.Response
	var err error

	switch method {
	case "HubVirtualNetworkConnectionsClient.BeginCreateOrUpdate":
		resp, err = h.dispatchBeginCreateOrUpdate(req)
	case "HubVirtualNetworkConnectionsClient.BeginDelete":
		resp, err = h.dispatchBeginDelete(req)
	case "HubVirtualNetworkConnectionsClient.Get":
		resp, err = h.dispatchGet(req)
	case "HubVirtualNetworkConnectionsClient.NewListPager":
		resp, err = h.dispatchNewListPager(req)
	default:
		err = fmt.Errorf("unhandled API %s", method)
	}

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (h *HubVirtualNetworkConnectionsServerTransport) dispatchBeginCreateOrUpdate(req *http.Request) (*http.Response, error) {
	if h.srv.BeginCreateOrUpdate == nil {
		return nil, &nonRetriableError{errors.New("fake for method BeginCreateOrUpdate not implemented")}
	}
	beginCreateOrUpdate := h.beginCreateOrUpdate.get(req)
	if beginCreateOrUpdate == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/resourceGroups/(?P<resourceGroupName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Microsoft\.Network/virtualHubs/(?P<virtualHubName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/hubVirtualNetworkConnections/(?P<connectionName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if matches == nil || len(matches) < 4 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		body, err := server.UnmarshalRequestAsJSON[armnetwork.HubVirtualNetworkConnection](req)
		if err != nil {
			return nil, err
		}
		resourceGroupNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("resourceGroupName")])
		if err != nil {
			return nil, err
		}
		virtualHubNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("virtualHubName")])
		if err != nil {
			return nil, err
		}
		connectionNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("connectionName")])
		if err != nil {
			return nil, err
		}
		respr, errRespr := h.srv.BeginCreateOrUpdate(req.Context(), resourceGroupNameParam, virtualHubNameParam, connectionNameParam, body, nil)
		if respErr := server.GetError(errRespr, req); respErr != nil {
			return nil, respErr
		}
		beginCreateOrUpdate = &respr
		h.beginCreateOrUpdate.add(req, beginCreateOrUpdate)
	}

	resp, err := server.PollerResponderNext(beginCreateOrUpdate, req)
	if err != nil {
		return nil, err
	}

	if !contains([]int{http.StatusOK, http.StatusCreated}, resp.StatusCode) {
		h.beginCreateOrUpdate.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK, http.StatusCreated", resp.StatusCode)}
	}
	if !server.PollerResponderMore(beginCreateOrUpdate) {
		h.beginCreateOrUpdate.remove(req)
	}

	return resp, nil
}

func (h *HubVirtualNetworkConnectionsServerTransport) dispatchBeginDelete(req *http.Request) (*http.Response, error) {
	if h.srv.BeginDelete == nil {
		return nil, &nonRetriableError{errors.New("fake for method BeginDelete not implemented")}
	}
	beginDelete := h.beginDelete.get(req)
	if beginDelete == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/resourceGroups/(?P<resourceGroupName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Microsoft\.Network/virtualHubs/(?P<virtualHubName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/hubVirtualNetworkConnections/(?P<connectionName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if matches == nil || len(matches) < 4 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		resourceGroupNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("resourceGroupName")])
		if err != nil {
			return nil, err
		}
		virtualHubNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("virtualHubName")])
		if err != nil {
			return nil, err
		}
		connectionNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("connectionName")])
		if err != nil {
			return nil, err
		}
		respr, errRespr := h.srv.BeginDelete(req.Context(), resourceGroupNameParam, virtualHubNameParam, connectionNameParam, nil)
		if respErr := server.GetError(errRespr, req); respErr != nil {
			return nil, respErr
		}
		beginDelete = &respr
		h.beginDelete.add(req, beginDelete)
	}

	resp, err := server.PollerResponderNext(beginDelete, req)
	if err != nil {
		return nil, err
	}

	if !contains([]int{http.StatusOK, http.StatusAccepted, http.StatusNoContent}, resp.StatusCode) {
		h.beginDelete.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK, http.StatusAccepted, http.StatusNoContent", resp.StatusCode)}
	}
	if !server.PollerResponderMore(beginDelete) {
		h.beginDelete.remove(req)
	}

	return resp, nil
}

func (h *HubVirtualNetworkConnectionsServerTransport) dispatchGet(req *http.Request) (*http.Response, error) {
	if h.srv.Get == nil {
		return nil, &nonRetriableError{errors.New("fake for method Get not implemented")}
	}
	const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/resourceGroups/(?P<resourceGroupName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Microsoft\.Network/virtualHubs/(?P<virtualHubName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/hubVirtualNetworkConnections/(?P<connectionName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)`
	regex := regexp.MustCompile(regexStr)
	matches := regex.FindStringSubmatch(req.URL.EscapedPath())
	if matches == nil || len(matches) < 4 {
		return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
	}
	resourceGroupNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("resourceGroupName")])
	if err != nil {
		return nil, err
	}
	virtualHubNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("virtualHubName")])
	if err != nil {
		return nil, err
	}
	connectionNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("connectionName")])
	if err != nil {
		return nil, err
	}
	respr, errRespr := h.srv.Get(req.Context(), resourceGroupNameParam, virtualHubNameParam, connectionNameParam, nil)
	if respErr := server.GetError(errRespr, req); respErr != nil {
		return nil, respErr
	}
	respContent := server.GetResponseContent(respr)
	if !contains([]int{http.StatusOK}, respContent.HTTPStatus) {
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK", respContent.HTTPStatus)}
	}
	resp, err := server.MarshalResponseAsJSON(respContent, server.GetResponse(respr).HubVirtualNetworkConnection, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (h *HubVirtualNetworkConnectionsServerTransport) dispatchNewListPager(req *http.Request) (*http.Response, error) {
	if h.srv.NewListPager == nil {
		return nil, &nonRetriableError{errors.New("fake for method NewListPager not implemented")}
	}
	newListPager := h.newListPager.get(req)
	if newListPager == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/resourceGroups/(?P<resourceGroupName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Microsoft\.Network/virtualHubs/(?P<virtualHubName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/hubVirtualNetworkConnections`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if matches == nil || len(matches) < 3 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		resourceGroupNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("resourceGroupName")])
		if err != nil {
			return nil, err
		}
		virtualHubNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("virtualHubName")])
		if err != nil {
			return nil, err
		}
		resp := h.srv.NewListPager(resourceGroupNameParam, virtualHubNameParam, nil)
		newListPager = &resp
		h.newListPager.add(req, newListPager)
		server.PagerResponderInjectNextLinks(newListPager, req, func(page *armnetwork.HubVirtualNetworkConnectionsClientListResponse, createLink func() string) {
			page.NextLink = to.Ptr(createLink())
		})
	}
	resp, err := server.PagerResponderNext(newListPager, req)
	if err != nil {
		return nil, err
	}
	if !contains([]int{http.StatusOK}, resp.StatusCode) {
		h.newListPager.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK", resp.StatusCode)}
	}
	if !server.PagerResponderMore(newListPager) {
		h.newListPager.remove(req)
	}
	return resp, nil
}