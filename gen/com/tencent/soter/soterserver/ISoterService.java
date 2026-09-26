/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: E:\\Buildcache\\android-sdk-codex\\build-tools\\36.0.0\\aidl.exe -ID:\\Users\\Andrea-TB\\Desktop\\ommega\\.tmp-driver\\aidlroot -oD:\\Users\\Andrea-TB\\Desktop\\ommega\\.tmp-driver\\gen D:\\Users\\Andrea-TB\\Desktop\\ommega\\.tmp-driver\\aidlroot\\com\\tencent\\soter\\soterserver\\ISoterService.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
package com.tencent.soter.soterserver;
public interface ISoterService extends android.os.IInterface
{
  /** Default implementation for ISoterService. */
  public static class Default implements com.tencent.soter.soterserver.ISoterService
  {
    /**
     * Demonstrates some basic types that you can use as parameters
     * and return values in AIDL.
     */
    @Override public int generateAppSecureKey(int uid) throws android.os.RemoteException
    {
      return 0;
    }
    @Override public com.tencent.soter.soterserver.SoterExportResult getAppSecureKey(int uid) throws android.os.RemoteException
    {
      return null;
    }
    @Override public boolean hasAskAlready(int uid) throws android.os.RemoteException
    {
      return false;
    }
    @Override public int generateAuthKey(int uid, java.lang.String kname) throws android.os.RemoteException
    {
      return 0;
    }
    @Override public int removeAuthKey(int uid, java.lang.String kname) throws android.os.RemoteException
    {
      return 0;
    }
    @Override public com.tencent.soter.soterserver.SoterExportResult getAuthKey(int uid, java.lang.String kname) throws android.os.RemoteException
    {
      return null;
    }
    @Override public int removeAllAuthKey(int uid) throws android.os.RemoteException
    {
      return 0;
    }
    @Override public boolean hasAuthKey(int uid, java.lang.String kname) throws android.os.RemoteException
    {
      return false;
    }
    @Override public com.tencent.soter.soterserver.SoterSessionResult initSigh(int uid, java.lang.String kname, java.lang.String challenge) throws android.os.RemoteException
    {
      return null;
    }
    @Override public com.tencent.soter.soterserver.SoterSignResult finishSign(long signSession) throws android.os.RemoteException
    {
      return null;
    }
    @Override public com.tencent.soter.soterserver.SoterDeviceResult getDeviceId() throws android.os.RemoteException
    {
      return null;
    }
    @Override public int getVersion() throws android.os.RemoteException
    {
      return 0;
    }
    @Override public com.tencent.soter.soterserver.SoterExtraParam getExtraParam(java.lang.String key) throws android.os.RemoteException
    {
      return null;
    }
    @Override
    public android.os.IBinder asBinder() {
      return null;
    }
  }
  /** Local-side IPC implementation stub class. */
  public static abstract class Stub extends android.os.Binder implements com.tencent.soter.soterserver.ISoterService
  {
    /** Construct the stub and attach it to the interface. */
    @SuppressWarnings("this-escape")
    public Stub()
    {
      this.attachInterface(this, DESCRIPTOR);
    }
    /**
     * Cast an IBinder object into an com.tencent.soter.soterserver.ISoterService interface,
     * generating a proxy if needed.
     */
    public static com.tencent.soter.soterserver.ISoterService asInterface(android.os.IBinder obj)
    {
      if ((obj==null)) {
        return null;
      }
      android.os.IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
      if (((iin!=null)&&(iin instanceof com.tencent.soter.soterserver.ISoterService))) {
        return ((com.tencent.soter.soterserver.ISoterService)iin);
      }
      return new com.tencent.soter.soterserver.ISoterService.Stub.Proxy(obj);
    }
    @Override public android.os.IBinder asBinder()
    {
      return this;
    }
    @Override public boolean onTransact(int code, android.os.Parcel data, android.os.Parcel reply, int flags) throws android.os.RemoteException
    {
      java.lang.String descriptor = DESCRIPTOR;
      if (code >= android.os.IBinder.FIRST_CALL_TRANSACTION && code <= android.os.IBinder.LAST_CALL_TRANSACTION) {
        data.enforceInterface(descriptor);
      }
      if (code == INTERFACE_TRANSACTION) {
        reply.writeString(descriptor);
        return true;
      }
      switch (code)
      {
        case TRANSACTION_generateAppSecureKey:
        {
          int _arg0;
          _arg0 = data.readInt();
          int _result = this.generateAppSecureKey(_arg0);
          reply.writeNoException();
          reply.writeInt(_result);
          break;
        }
        case TRANSACTION_getAppSecureKey:
        {
          int _arg0;
          _arg0 = data.readInt();
          com.tencent.soter.soterserver.SoterExportResult _result = this.getAppSecureKey(_arg0);
          reply.writeNoException();
          _Parcel.writeTypedObject(reply, _result, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
          break;
        }
        case TRANSACTION_hasAskAlready:
        {
          int _arg0;
          _arg0 = data.readInt();
          boolean _result = this.hasAskAlready(_arg0);
          reply.writeNoException();
          reply.writeInt(((_result)?(1):(0)));
          break;
        }
        case TRANSACTION_generateAuthKey:
        {
          int _arg0;
          _arg0 = data.readInt();
          java.lang.String _arg1;
          _arg1 = data.readString();
          int _result = this.generateAuthKey(_arg0, _arg1);
          reply.writeNoException();
          reply.writeInt(_result);
          break;
        }
        case TRANSACTION_removeAuthKey:
        {
          int _arg0;
          _arg0 = data.readInt();
          java.lang.String _arg1;
          _arg1 = data.readString();
          int _result = this.removeAuthKey(_arg0, _arg1);
          reply.writeNoException();
          reply.writeInt(_result);
          break;
        }
        case TRANSACTION_getAuthKey:
        {
          int _arg0;
          _arg0 = data.readInt();
          java.lang.String _arg1;
          _arg1 = data.readString();
          com.tencent.soter.soterserver.SoterExportResult _result = this.getAuthKey(_arg0, _arg1);
          reply.writeNoException();
          _Parcel.writeTypedObject(reply, _result, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
          break;
        }
        case TRANSACTION_removeAllAuthKey:
        {
          int _arg0;
          _arg0 = data.readInt();
          int _result = this.removeAllAuthKey(_arg0);
          reply.writeNoException();
          reply.writeInt(_result);
          break;
        }
        case TRANSACTION_hasAuthKey:
        {
          int _arg0;
          _arg0 = data.readInt();
          java.lang.String _arg1;
          _arg1 = data.readString();
          boolean _result = this.hasAuthKey(_arg0, _arg1);
          reply.writeNoException();
          reply.writeInt(((_result)?(1):(0)));
          break;
        }
        case TRANSACTION_initSigh:
        {
          int _arg0;
          _arg0 = data.readInt();
          java.lang.String _arg1;
          _arg1 = data.readString();
          java.lang.String _arg2;
          _arg2 = data.readString();
          com.tencent.soter.soterserver.SoterSessionResult _result = this.initSigh(_arg0, _arg1, _arg2);
          reply.writeNoException();
          _Parcel.writeTypedObject(reply, _result, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
          break;
        }
        case TRANSACTION_finishSign:
        {
          long _arg0;
          _arg0 = data.readLong();
          com.tencent.soter.soterserver.SoterSignResult _result = this.finishSign(_arg0);
          reply.writeNoException();
          _Parcel.writeTypedObject(reply, _result, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
          break;
        }
        case TRANSACTION_getDeviceId:
        {
          com.tencent.soter.soterserver.SoterDeviceResult _result = this.getDeviceId();
          reply.writeNoException();
          _Parcel.writeTypedObject(reply, _result, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
          break;
        }
        case TRANSACTION_getVersion:
        {
          int _result = this.getVersion();
          reply.writeNoException();
          reply.writeInt(_result);
          break;
        }
        case TRANSACTION_getExtraParam:
        {
          java.lang.String _arg0;
          _arg0 = data.readString();
          com.tencent.soter.soterserver.SoterExtraParam _result = this.getExtraParam(_arg0);
          reply.writeNoException();
          _Parcel.writeTypedObject(reply, _result, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
          break;
        }
        default:
        {
          return super.onTransact(code, data, reply, flags);
        }
      }
      return true;
    }
    private static class Proxy implements com.tencent.soter.soterserver.ISoterService
    {
      private android.os.IBinder mRemote;
      Proxy(android.os.IBinder remote)
      {
        mRemote = remote;
      }
      @Override public android.os.IBinder asBinder()
      {
        return mRemote;
      }
      public java.lang.String getInterfaceDescriptor()
      {
        return DESCRIPTOR;
      }
      /**
       * Demonstrates some basic types that you can use as parameters
       * and return values in AIDL.
       */
      @Override public int generateAppSecureKey(int uid) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        int _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeInt(uid);
          boolean _status = mRemote.transact(Stub.TRANSACTION_generateAppSecureKey, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readInt();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public com.tencent.soter.soterserver.SoterExportResult getAppSecureKey(int uid) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        com.tencent.soter.soterserver.SoterExportResult _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeInt(uid);
          boolean _status = mRemote.transact(Stub.TRANSACTION_getAppSecureKey, _data, _reply, 0);
          _reply.readException();
          _result = _Parcel.readTypedObject(_reply, com.tencent.soter.soterserver.SoterExportResult.CREATOR);
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public boolean hasAskAlready(int uid) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        boolean _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeInt(uid);
          boolean _status = mRemote.transact(Stub.TRANSACTION_hasAskAlready, _data, _reply, 0);
          _reply.readException();
          _result = (0!=_reply.readInt());
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public int generateAuthKey(int uid, java.lang.String kname) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        int _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeInt(uid);
          _data.writeString(kname);
          boolean _status = mRemote.transact(Stub.TRANSACTION_generateAuthKey, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readInt();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public int removeAuthKey(int uid, java.lang.String kname) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        int _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeInt(uid);
          _data.writeString(kname);
          boolean _status = mRemote.transact(Stub.TRANSACTION_removeAuthKey, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readInt();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public com.tencent.soter.soterserver.SoterExportResult getAuthKey(int uid, java.lang.String kname) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        com.tencent.soter.soterserver.SoterExportResult _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeInt(uid);
          _data.writeString(kname);
          boolean _status = mRemote.transact(Stub.TRANSACTION_getAuthKey, _data, _reply, 0);
          _reply.readException();
          _result = _Parcel.readTypedObject(_reply, com.tencent.soter.soterserver.SoterExportResult.CREATOR);
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public int removeAllAuthKey(int uid) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        int _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeInt(uid);
          boolean _status = mRemote.transact(Stub.TRANSACTION_removeAllAuthKey, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readInt();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public boolean hasAuthKey(int uid, java.lang.String kname) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        boolean _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeInt(uid);
          _data.writeString(kname);
          boolean _status = mRemote.transact(Stub.TRANSACTION_hasAuthKey, _data, _reply, 0);
          _reply.readException();
          _result = (0!=_reply.readInt());
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public com.tencent.soter.soterserver.SoterSessionResult initSigh(int uid, java.lang.String kname, java.lang.String challenge) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        com.tencent.soter.soterserver.SoterSessionResult _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeInt(uid);
          _data.writeString(kname);
          _data.writeString(challenge);
          boolean _status = mRemote.transact(Stub.TRANSACTION_initSigh, _data, _reply, 0);
          _reply.readException();
          _result = _Parcel.readTypedObject(_reply, com.tencent.soter.soterserver.SoterSessionResult.CREATOR);
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public com.tencent.soter.soterserver.SoterSignResult finishSign(long signSession) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        com.tencent.soter.soterserver.SoterSignResult _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeLong(signSession);
          boolean _status = mRemote.transact(Stub.TRANSACTION_finishSign, _data, _reply, 0);
          _reply.readException();
          _result = _Parcel.readTypedObject(_reply, com.tencent.soter.soterserver.SoterSignResult.CREATOR);
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public com.tencent.soter.soterserver.SoterDeviceResult getDeviceId() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        com.tencent.soter.soterserver.SoterDeviceResult _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_getDeviceId, _data, _reply, 0);
          _reply.readException();
          _result = _Parcel.readTypedObject(_reply, com.tencent.soter.soterserver.SoterDeviceResult.CREATOR);
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public int getVersion() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        int _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_getVersion, _data, _reply, 0);
          _reply.readException();
          _result = _reply.readInt();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
      @Override public com.tencent.soter.soterserver.SoterExtraParam getExtraParam(java.lang.String key) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        com.tencent.soter.soterserver.SoterExtraParam _result;
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeString(key);
          boolean _status = mRemote.transact(Stub.TRANSACTION_getExtraParam, _data, _reply, 0);
          _reply.readException();
          _result = _Parcel.readTypedObject(_reply, com.tencent.soter.soterserver.SoterExtraParam.CREATOR);
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
        return _result;
      }
    }
    static final int TRANSACTION_generateAppSecureKey = (android.os.IBinder.FIRST_CALL_TRANSACTION + 0);
    static final int TRANSACTION_getAppSecureKey = (android.os.IBinder.FIRST_CALL_TRANSACTION + 1);
    static final int TRANSACTION_hasAskAlready = (android.os.IBinder.FIRST_CALL_TRANSACTION + 2);
    static final int TRANSACTION_generateAuthKey = (android.os.IBinder.FIRST_CALL_TRANSACTION + 3);
    static final int TRANSACTION_removeAuthKey = (android.os.IBinder.FIRST_CALL_TRANSACTION + 4);
    static final int TRANSACTION_getAuthKey = (android.os.IBinder.FIRST_CALL_TRANSACTION + 5);
    static final int TRANSACTION_removeAllAuthKey = (android.os.IBinder.FIRST_CALL_TRANSACTION + 6);
    static final int TRANSACTION_hasAuthKey = (android.os.IBinder.FIRST_CALL_TRANSACTION + 7);
    static final int TRANSACTION_initSigh = (android.os.IBinder.FIRST_CALL_TRANSACTION + 8);
    static final int TRANSACTION_finishSign = (android.os.IBinder.FIRST_CALL_TRANSACTION + 9);
    static final int TRANSACTION_getDeviceId = (android.os.IBinder.FIRST_CALL_TRANSACTION + 10);
    static final int TRANSACTION_getVersion = (android.os.IBinder.FIRST_CALL_TRANSACTION + 11);
    static final int TRANSACTION_getExtraParam = (android.os.IBinder.FIRST_CALL_TRANSACTION + 12);
  }
  /** @hide */
  public static final java.lang.String DESCRIPTOR = "com.tencent.soter.soterserver.ISoterService";
  /**
   * Demonstrates some basic types that you can use as parameters
   * and return values in AIDL.
   */
  public int generateAppSecureKey(int uid) throws android.os.RemoteException;
  public com.tencent.soter.soterserver.SoterExportResult getAppSecureKey(int uid) throws android.os.RemoteException;
  public boolean hasAskAlready(int uid) throws android.os.RemoteException;
  public int generateAuthKey(int uid, java.lang.String kname) throws android.os.RemoteException;
  public int removeAuthKey(int uid, java.lang.String kname) throws android.os.RemoteException;
  public com.tencent.soter.soterserver.SoterExportResult getAuthKey(int uid, java.lang.String kname) throws android.os.RemoteException;
  public int removeAllAuthKey(int uid) throws android.os.RemoteException;
  public boolean hasAuthKey(int uid, java.lang.String kname) throws android.os.RemoteException;
  public com.tencent.soter.soterserver.SoterSessionResult initSigh(int uid, java.lang.String kname, java.lang.String challenge) throws android.os.RemoteException;
  public com.tencent.soter.soterserver.SoterSignResult finishSign(long signSession) throws android.os.RemoteException;
  public com.tencent.soter.soterserver.SoterDeviceResult getDeviceId() throws android.os.RemoteException;
  public int getVersion() throws android.os.RemoteException;
  public com.tencent.soter.soterserver.SoterExtraParam getExtraParam(java.lang.String key) throws android.os.RemoteException;
  /** @hide */
  static class _Parcel {
    static private <T> T readTypedObject(
        android.os.Parcel parcel,
        android.os.Parcelable.Creator<T> c) {
      if (parcel.readInt() != 0) {
          return c.createFromParcel(parcel);
      } else {
          return null;
      }
    }
    static private <T extends android.os.Parcelable> void writeTypedObject(
        android.os.Parcel parcel, T value, int parcelableFlags) {
      if (value != null) {
        parcel.writeInt(1);
        value.writeToParcel(parcel, parcelableFlags);
      } else {
        parcel.writeInt(0);
      }
    }
  }
}
