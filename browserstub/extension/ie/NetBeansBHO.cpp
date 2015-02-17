
/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common
 * Development and Distribution License("CDDL") (collectively, the
 * "License"). You may not use this file except in compliance with the
 * License. You can obtain a copy of the License at
 * http://www.netbeans.org/cddl-gplv2.html
 * or nbbuild/licenses/CDDL-GPL-2-CP. See the License for the
 * specific language governing permissions and limitations under the
 * License.  When distributing the software, include this License Header
 * Notice in each file and include the License file at
 * nbbuild/licenses/CDDL-GPL-2-CP.  Sun designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Sun in the GPL Version 2 section of the License file that
 * accompanied this code. If applicable, add the following below the
 * License Header, with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 * If you wish your version of this file to be governed by only the CDDL
 * or only the GPL Version 2, indicate your decision by adding
 * "[Contributor] elects to include this software in this distribution
 * under the [CDDL or GPL Version 2] license." If you do not indicate a
 * single choice of license, a recipient has the option to distribute
 * your version of this file under either the CDDL, the GPL Version 2 or
 * to extend the choice of license to its licensees as provided above.
 * However, if you add GPL Version 2 code and therefore, elected the GPL
 * Version 2 license, then the option applies only if the new code is
 * made subject to such option by the copyright holder.
 *
 * Contributor(s):
 *      jdeva <deva@neteans.org>
 *
 * Portions Copyrighted 2008 Sun Microsystems, Inc.
 */
#include "stdafx.h"
#include "NetbeansBHO.h"
#include "ScriptDebugger.h"
#include "Utils.h"

// NetbeansBHO

HRESULT CNetBeansBHO::FinalConstruct() {
    m_dwThreadID = GetCurrentThreadId();
    debuggerStarted = FALSE;
	m_hEvent = CreateEvent(NULL, false, false, NULL);
//    m_pScriptDebugger = NULL;
    return S_OK;
}

void CNetBeansBHO::FinalRelease() {
  
   debuggerStarted = FALSE;
    SetEvent(m_hEvent);
}

STDMETHODIMP CNetBeansBHO::SetSite(IUnknown* pUnkSite) {
    USES_CONVERSION;
    HRESULT hr = E_FAIL;
    if (pUnkSite != NULL) {
        hr = pUnkSite->QueryInterface(IID_IWebBrowser2, (void**)&m_spWebBrowser);
        if (SUCCEEDED(hr)) {
            // Register DWebBrowserEvents2
            hr = DispEventAdvise(m_spWebBrowser);
            if (SUCCEEDED(hr)) {
                m_bAdvised = TRUE;
            }
        }
        Utils::registerInterfaceInGlobal(m_spWebBrowser, IID_IWebBrowser2, &m_dwWebBrowserCookie);
    } else {
        // Unregister DWebBrowserEvents2
        if (m_bAdvised) {
            DispEventUnadvise(m_spWebBrowser);
            m_bAdvised = FALSE;
        }
        Utils::revokeInterfaceFromGlobal(m_dwWebBrowserCookie);
        m_spWebBrowser.Release();
    }


	
    return IObjectWithSiteImpl<CNetBeansBHO>::SetSite(pUnkSite);
}

HRESULT CNetBeansBHO::getWebBrowser(IWebBrowser2 **ppWebBrowser) {
    HRESULT hr = S_OK;
    if(m_dwThreadID == GetCurrentThreadId()) {
        *ppWebBrowser = m_spWebBrowser;
    }else {
        hr = Utils::getInterfaceFromGlobal(m_dwWebBrowserCookie, IID_IWebBrowser2, 
                                            (void **)ppWebBrowser);
    }
    return hr;
}


void STDMETHODCALLTYPE CNetBeansBHO::OnNavigateComplete(IDispatch *pDisp, VARIANT *pvarURL) {
	//initial debug interface
	
    //if(!debuggerStarted) {	
        checkAndInitNetbeansDebugging();
   // }
}

/*
void STDMETHODCALLTYPE CNetBeansBHO::OnBeforeNavigate(IDispatch *pDisp, VARIANT *pvarURL){
	 
	     //checkAndInitNetbeansDebugging(pvarURL->bstrVal);

}
*/
void STDMETHODCALLTYPE CNetBeansBHO::OnDocumentComplete(IDispatch *pDisp, VARIANT *pvarURL) {
	HWND hwnd;
	HRESULT hr = m_spWebBrowser->get_HWND((LONG_PTR *)&hwnd);
	if(SUCCEEDED(hr)){
	
		//MessageBox(hwnd,L"HELLO WORLD FIRST BHO TSS!",L"BHO", MB_OK);
	}
	/*
		CComPtr<IDispatch> spDisp;
        m_spWebBrowser->get_Document(&spDisp);
        CComQIPtr<IHTMLDocument2> spHtmlDocument = spDisp;
        CComBSTR bstrState;
        spHtmlDocument->get_readyState(&bstrState);
        if(bstrState == "complete") {
			MessageBox(hwnd,L"COMPLETE",L"BHO", MB_OK);
            m_pDbgpConnection->sendWindowsMessage(spHtmlDocument);
            m_pDbgpConnection->sendSourcesMessage(spHtmlDocument);
        }
    }else {
        if(m_pDbgpConnection != NULL) {
            debuggerStarted = TRUE;
        }
    }
	*/
	// if(m_pDbgpConnection != NULL) {
      //      debuggerStarted = TRUE;

			CComPtr<IDispatch> spDisp;
			CComPtr<IHTMLElement> pBody;
			BSTR htmlTEXT;
        m_spWebBrowser->get_Document(&spDisp);
        CComQIPtr<IHTMLDocument2> spHtmlDocument = spDisp;
		spHtmlDocument->get_body(&pBody);
		//spHtmlDocument->
		
		pBody->get_outerHTML(&htmlTEXT);
	//	MessageBox(hwnd,htmlTEXT,L"BHO", MB_OK);

        CComBSTR bstrState;
        spHtmlDocument->get_readyState(&bstrState);
        if(bstrState == "complete") {
           // m_pDbgpConnection->sendWindowsMessage(spHtmlDocument);
          //  m_pDbgpConnection->sendSourcesMessage(spHtmlDocument);
        }
   //    }

	

}

void CNetBeansBHO::checkAndInitNetbeansDebugging() {
 
 DWORD threadID;

 CreateThread(NULL, 0, CNetBeansBHO::DebuggerProc, this, 0, &threadID);

}

/*
void CNetBeansBHO::initializeNetbeansDebugging(tstring port, tstring sessionId) {
    DWORD threadID;
  //  m_pDbgpConnection = new DbgpConnection(port, sessionId, m_dwWebBrowserCookie);
    //DebugBreak();
  //  if(m_pDbgpConnection->connectToIDE()) {
        //Create thread for debugger
        CreateThread(NULL, 0, CNetBeansBHO::DebuggerProc, this, 0, &threadID);
   // }
}
*/
DWORD WINAPI CNetBeansBHO::DebuggerProc(LPVOID param) {

    ::CoInitializeEx(NULL, COINIT_MULTITHREADED);
    CNetBeansBHO *pNetbeansBHO = (CNetBeansBHO*)param;
	ScriptDebugger *pScriptDebugger = ScriptDebugger::createScriptDebugger(pNetbeansBHO->m_dwWebBrowserCookie);
  

    if(pScriptDebugger != NULL) {
	    pScriptDebugger->inialBrowserstub();
		
        HRESULT hr = pScriptDebugger->startSession();
        if(hr == S_OK) {
            DWORD threadID;
           
            //Thread for DBGP command and responses
          //  CreateThread(NULL, 0, DbgpConnection::commandHandler, 
            //                pNetbeansBHO->m_pDbgpConnection, 0, &threadID);
            AtlWaitWithMessageLoop(pNetbeansBHO->m_hEvent);
        }
	
    }


  //  pScriptDebugger->Release();
	::CoUninitialize();

    return 0;
}