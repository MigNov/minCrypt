#include <wx/wx.h>

/* Class definition */
class MinCrypt : public wxApp
{
  public:
	virtual bool OnInit();
};

class MainFrame : public wxFrame
{
  public:
	MainFrame(const wxString& title, const wxPoint& pos, const wxSize& size);
	void OnQuit(wxCommandEvent& event);
	void OnAbout(wxCommandEvent& event);
	void OnOpenInput(wxCommandEvent& event);
	void OnSaveOutput(wxCommandEvent& event);
	void OnProcess(wxCommandEvent& event);

	wxTextCtrl *inf;
	wxTextCtrl *outf;
	wxTextCtrl *pwd;
	wxTextCtrl *salt;
	wxCheckBox *dec;
};

enum
{
	ID_Quit=1,
	ID_OpenInput,
	ID_SaveOutput,
	ID_About,
	ID_Process
};

/* Function prototypes */
char *wxStringChar(wxString str);
wxString selectFileName(wxFrame *frame, int savedlg);

